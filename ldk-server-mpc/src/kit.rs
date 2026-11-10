//! Channel kits: precomputed per-commitment (revocation) secrets, threshold-encrypted.
//!
//! BOLT 3 derives a channel's per-commitment secrets from one seed through a SHA-256 hash tree,
//! and the counterparty checks every secret it receives against that tree. Hashes cannot be
//! computed on key shares, so whoever holds the seed holds every future secret of the channel.
//! To keep the seed off every online machine, an offline ceremony
//!
//! 1. reassembles the master seed from its custodians' pieces ([`combine_seed`]),
//! 2. derives a channel seed for each kit, computes the secrets and their public points, and
//! 3. encrypts each secret under the parties' joint TDH2 key ([`crate::tdh2`]), bound by a label
//!    to the kit and the commitment number ([`generate_segment`]).
//!
//! The parties get the resulting kit files. They hold only ciphertexts and public points; a
//! secret is recovered when every party contributes a partial decryption, which each does only
//! after its own policy allows that release.
//!
//! A kit is made before any channel exists and is bound to a channel on first use
//! ([`KitStore::bind_unbound`]). It covers commitment numbers in segments, counting down from
//! [`INITIAL_COMMITMENT_NUMBER`]; the ceremony adds a segment before a channel runs out.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use hex_conservative::{DisplayHex, FromHex};
use lightning::ln::chan_utils;

use crate::protocol::ChannelId;
use crate::tdh2;

pub type KitId = [u8; 32];

/// The first commitment number of every channel; numbers count down (BOLT 3).
pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

const MAGIC: &[u8; 8] = b"LSMKIT1\0";
const HEADER_LEN: u64 = 8 + 32 + 32 + 8 + 4 + 4;
const POINT_LEN: usize = 33;

/// The TDH2 label of the secret for commitment `idx` of kit `kit_id`. A ciphertext only
/// decrypts under the label it was made with, so one secret cannot be passed off as another.
pub fn label(kit_id: &KitId, idx: u64) -> Vec<u8> {
	let mut out = b"ldk-server-mpc/revocation/v1".to_vec();
	out.extend_from_slice(kit_id);
	out.extend_from_slice(&idx.to_be_bytes());
	out
}

/// Identifies the TDH2 key a kit was encrypted to.
pub fn public_key_id(tdh2_public_key: &[u8]) -> [u8; 32] {
	sha256::Hash::hash(tdh2_public_key).to_byte_array()
}

/// The BOLT 3 commitment seed of kit `kit_id` under `master_seed`.
fn kit_seed(master_seed: &[u8; 32], kit_id: &KitId) -> [u8; 32] {
	let mut engine = sha256::Hash::engine();
	engine.input(b"ldk-server-mpc/kit-seed/v1");
	engine.input(master_seed);
	engine.input(kit_id);
	sha256::Hash::from_engine(engine).to_byte_array()
}

/// Ceremony step: builds one kit segment covering `count` commitment numbers from
/// `first_index` downwards. Returns the file contents; name the file with [`segment_file_name`].
///
/// Run this only on the offline machine that holds the reassembled `master_seed`.
pub fn generate_segment(
	master_seed: &[u8; 32], kit_id: &KitId, tdh2_public_key: &[u8], first_index: u64, count: u32,
) -> Result<Vec<u8>, String> {
	if count == 0 || first_index > INITIAL_COMMITMENT_NUMBER || (count as u64 - 1) > first_index {
		return Err("segment range is outside the commitment numbers".into());
	}
	let seed = kit_seed(master_seed, kit_id);
	let secp = Secp256k1::new();
	let mut records = Vec::with_capacity(count as usize);
	let mut ct_max = 0usize;
	for i in 0..count as u64 {
		let idx = first_index - i;
		let secret = chan_utils::build_commitment_secret(&seed, idx);
		let key = SecretKey::from_slice(&secret).map_err(|e| e.to_string())?;
		let point = PublicKey::from_secret_key(&secp, &key).serialize();
		let ct = tdh2::encrypt(tdh2_public_key, &secret, &label(kit_id, idx))
			.map_err(|e| e.to_string())?;
		if ct.len() > u16::MAX as usize {
			return Err("ciphertext too large".into());
		}
		ct_max = ct_max.max(ct.len());
		records.push((point, ct));
	}
	let record_len = POINT_LEN + 2 + ct_max;
	let mut out = Vec::with_capacity(HEADER_LEN as usize + record_len * records.len());
	out.extend_from_slice(MAGIC);
	out.extend_from_slice(kit_id);
	out.extend_from_slice(&public_key_id(tdh2_public_key));
	out.extend_from_slice(&first_index.to_be_bytes());
	out.extend_from_slice(&count.to_be_bytes());
	out.extend_from_slice(&(record_len as u32).to_be_bytes());
	for (point, ct) in records {
		out.extend_from_slice(&point);
		out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
		out.extend_from_slice(&ct);
		out.resize(out.len() + (ct_max - ct.len()), 0);
	}
	Ok(out)
}

pub fn segment_file_name(kit_id: &KitId, first_index: u64) -> String {
	format!("{}.{:012x}.kit", kit_id.as_hex(), first_index)
}

/// One commitment number's entry in a kit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitRecord {
	pub point: PublicKey,
	pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Segment {
	path: PathBuf,
	public_key_id: [u8; 32],
	first_index: u64,
	count: u32,
	record_len: u32,
}

impl Segment {
	fn read_header(path: &Path) -> io::Result<(KitId, Segment)> {
		let mut f = fs::File::open(path)?;
		let mut h = [0u8; HEADER_LEN as usize];
		f.read_exact(&mut h)?;
		if &h[..8] != MAGIC {
			return Err(bad("not a kit file"));
		}
		let kit_id: KitId = h[8..40].try_into().unwrap();
		let seg = Segment {
			path: path.to_path_buf(),
			public_key_id: h[40..72].try_into().unwrap(),
			first_index: u64::from_be_bytes(h[72..80].try_into().unwrap()),
			count: u32::from_be_bytes(h[80..84].try_into().unwrap()),
			record_len: u32::from_be_bytes(h[84..88].try_into().unwrap()),
		};
		if seg.count == 0
			|| (seg.record_len as usize) < POINT_LEN + 2
			|| seg.first_index > INITIAL_COMMITMENT_NUMBER
			|| (seg.count as u64 - 1) > seg.first_index
		{
			return Err(bad("malformed kit header"));
		}
		let expected = HEADER_LEN + seg.count as u64 * seg.record_len as u64;
		if f.metadata()?.len() != expected {
			return Err(bad("kit file has the wrong length"));
		}
		Ok((kit_id, seg))
	}

	fn covers(&self, idx: u64) -> bool {
		idx <= self.first_index && self.first_index - idx < self.count as u64
	}

	fn record(&self, idx: u64) -> io::Result<KitRecord> {
		let mut f = fs::File::open(&self.path)?;
		f.seek(SeekFrom::Start(HEADER_LEN + (self.first_index - idx) * self.record_len as u64))?;
		let mut rec = vec![0u8; self.record_len as usize];
		f.read_exact(&mut rec)?;
		let point = PublicKey::from_slice(&rec[..POINT_LEN]).map_err(|e| bad(e.to_string()))?;
		let ct_len = u16::from_be_bytes([rec[POINT_LEN], rec[POINT_LEN + 1]]) as usize;
		let ct = rec
			.get(POINT_LEN + 2..POINT_LEN + 2 + ct_len)
			.ok_or_else(|| bad("malformed kit record"))?;
		Ok(KitRecord { point, ciphertext: ct.to_vec() })
	}
}

fn bad(msg: impl Into<String>) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A party's directory of kit files and the record of which channel each kit serves.
pub struct KitStore {
	dir: PathBuf,
	/// Serializes binding so two channels cannot take the same kit.
	bind_lock: Mutex<()>,
	segments: Mutex<HashMap<KitId, Vec<Segment>>>,
}

impl KitStore {
	pub fn open(dir: &Path) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		Ok(KitStore {
			dir: dir.to_path_buf(),
			bind_lock: Mutex::new(()),
			segments: Mutex::new(HashMap::new()),
		})
	}

	pub fn dir(&self) -> &Path {
		&self.dir
	}

	/// Reads the headers of every kit file in the directory. Files added by a later ceremony
	/// are picked up here, so this runs again whenever a lookup misses.
	fn rescan(&self) -> io::Result<()> {
		let mut found: HashMap<KitId, Vec<Segment>> = HashMap::new();
		for entry in fs::read_dir(&self.dir)? {
			let path = entry?.path();
			if path.extension().map(|x| x == "kit").unwrap_or(false) {
				match Segment::read_header(&path) {
					Ok((kit_id, seg)) => found.entry(kit_id).or_default().push(seg),
					Err(e) => log::warn!("ignoring kit file {}: {e}", path.display()),
				}
			}
		}
		for segs in found.values_mut() {
			segs.sort_by_key(|s| std::cmp::Reverse(s.first_index));
		}
		*self.segments.lock().unwrap() = found;
		Ok(())
	}

	fn segment(&self, kit_id: &KitId, idx: u64) -> io::Result<Option<Segment>> {
		let find = |this: &Self| {
			this.segments
				.lock()
				.unwrap()
				.get(kit_id)
				.and_then(|segs| segs.iter().find(|s| s.covers(idx)).cloned())
		};
		if let Some(seg) = find(self) {
			return Ok(Some(seg));
		}
		self.rescan()?;
		Ok(find(self))
	}

	/// The point and ciphertext for commitment `idx`, or `None` if no segment covers it.
	pub fn record(&self, kit_id: &KitId, idx: u64) -> io::Result<Option<KitRecord>> {
		match self.segment(kit_id, idx)? {
			Some(seg) => seg.record(idx).map(Some),
			None => Ok(None),
		}
	}

	/// The TDH2 key the segment covering `idx` was encrypted to.
	pub fn public_key_id(&self, kit_id: &KitId, idx: u64) -> io::Result<Option<[u8; 32]>> {
		Ok(self.segment(kit_id, idx)?.map(|s| s.public_key_id))
	}

	/// How many commitment numbers from `idx` downwards the kit covers without a gap. Refill the
	/// kit before this reaches zero: a channel without a next point cannot move.
	pub fn remaining(&self, kit_id: &KitId, idx: u64) -> io::Result<u64> {
		self.rescan()?;
		let segments = self.segments.lock().unwrap();
		let Some(segs) = segments.get(kit_id) else { return Ok(0) };
		let mut next = idx;
		let mut total = 0u64;
		while let Some(seg) = segs.iter().find(|s| s.covers(next)) {
			let left = seg.count as u64 - (seg.first_index - next);
			total += left;
			if left > next {
				break;
			}
			next -= left;
		}
		Ok(total)
	}

	fn bound_path(&self, kit_id: &KitId) -> PathBuf {
		self.dir.join(format!("{}.bound", kit_id.as_hex()))
	}

	/// The channel a kit is bound to, if any.
	pub fn binding(&self, kit_id: &KitId) -> io::Result<Option<ChannelId>> {
		match fs::read_to_string(self.bound_path(kit_id)) {
			Ok(hex) => <[u8; 32]>::from_hex(hex.trim())
				.map(Some)
				.map_err(|e| bad(format!("bad kit binding: {e}"))),
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Binds `kit_id` to `channel`. A kit serves one channel for good: binding it again to the
	/// same channel is a no-op, to another channel an error.
	pub fn bind(&self, kit_id: &KitId, channel: &ChannelId) -> io::Result<()> {
		let _guard = self.bind_lock.lock().unwrap();
		if self.segment(kit_id, INITIAL_COMMITMENT_NUMBER)?.is_none() {
			return Err(io::Error::new(io::ErrorKind::NotFound, "no such kit"));
		}
		match self.binding(kit_id)? {
			Some(existing) if &existing == channel => return Ok(()),
			Some(_) => {
				return Err(io::Error::new(
					io::ErrorKind::AlreadyExists,
					"kit is bound to another channel",
				))
			},
			None => {},
		}
		let mut f =
			fs::OpenOptions::new().write(true).create_new(true).open(self.bound_path(kit_id))?;
		f.write_all(channel.as_hex().to_string().as_bytes())?;
		f.sync_all()
	}

	/// The kit already bound to `channel`, or else an unused kit encrypted to
	/// `tdh2_public_key`, which is then bound to it.
	pub fn bind_unbound(&self, channel: &ChannelId, tdh2_public_key: &[u8]) -> io::Result<KitId> {
		self.rescan()?;
		let mut kits: Vec<KitId> = self.segments.lock().unwrap().keys().copied().collect();
		kits.sort();
		for kit in &kits {
			if self.binding(kit)?.as_ref() == Some(channel) {
				return Ok(*kit);
			}
		}
		let want = public_key_id(tdh2_public_key);
		for kit in &kits {
			if self.binding(kit)?.is_some()
				|| self.public_key_id(kit, INITIAL_COMMITMENT_NUMBER)? != Some(want)
			{
				continue;
			}
			match self.bind(kit, channel) {
				Ok(()) => return Ok(*kit),
				Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
				Err(e) => return Err(e),
			}
		}
		Err(io::Error::new(
			io::ErrorKind::NotFound,
			"no unused channel kit: run the ceremony to add kits",
		))
	}

	/// The number of kits not yet bound to a channel.
	pub fn unbound_count(&self) -> io::Result<usize> {
		self.rescan()?;
		let kits: Vec<KitId> = self.segments.lock().unwrap().keys().copied().collect();
		let mut n = 0;
		for kit in kits {
			if self.binding(&kit)?.is_none() {
				n += 1;
			}
		}
		Ok(n)
	}
}

// ---------------------------------------------------------------------------
// Master seed custody: Shamir secret sharing over GF(256)
// ---------------------------------------------------------------------------

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
	let mut p = 0u8;
	while b != 0 {
		if b & 1 != 0 {
			p ^= a;
		}
		let carry = a & 0x80 != 0;
		a <<= 1;
		if carry {
			a ^= 0x1b;
		}
		b >>= 1;
	}
	p
}

fn gf_inv(a: u8) -> u8 {
	// a^254 in GF(256).
	let mut result = 1u8;
	let mut base = a;
	let mut exp = 254u8;
	while exp != 0 {
		if exp & 1 != 0 {
			result = gf_mul(result, base);
		}
		base = gf_mul(base, base);
		exp >>= 1;
	}
	result
}

/// One custodian's piece of the master seed: the piece number (1-based) and 32 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedPiece {
	pub number: u8,
	pub bytes: [u8; 32],
}

impl SeedPiece {
	pub fn to_hex(&self) -> String {
		format!("{:02x}{}", self.number, self.bytes.as_hex())
	}

	pub fn from_hex(hex: &str) -> Result<Self, String> {
		let raw = <[u8; 33]>::from_hex(hex.trim()).map_err(|e| format!("bad seed piece: {e}"))?;
		if raw[0] == 0 {
			return Err("bad seed piece: number 0".into());
		}
		Ok(SeedPiece { number: raw[0], bytes: raw[1..].try_into().unwrap() })
	}
}

/// Splits `seed` into `pieces` pieces, any `threshold` of which rebuild it; fewer reveal
/// nothing. `random` must return fresh random bytes.
pub fn split_seed(
	seed: &[u8; 32], threshold: u8, pieces: u8, mut random: impl FnMut(&mut [u8]),
) -> Result<Vec<SeedPiece>, String> {
	if threshold < 2 || pieces < threshold {
		return Err("need at least 2 pieces to rebuild and no more than exist".into());
	}
	let mut out: Vec<SeedPiece> =
		(1..=pieces).map(|number| SeedPiece { number, bytes: [0u8; 32] }).collect();
	let mut coeffs = vec![0u8; threshold as usize - 1];
	for (byte, secret) in seed.iter().enumerate() {
		random(&mut coeffs);
		for piece in out.iter_mut() {
			// Horner evaluation of secret + c1*x + c2*x^2 + ... at x = piece number.
			let mut y = 0u8;
			for c in coeffs.iter().rev() {
				y = gf_mul(y ^ c, piece.number);
			}
			piece.bytes[byte] = y ^ secret;
		}
	}
	for c in coeffs.iter_mut() {
		*c = 0;
	}
	Ok(out)
}

/// Rebuilds the master seed from `threshold` or more distinct pieces. With too few pieces, or
/// a wrong one, the result is a different seed; check it against the seed's fingerprint
/// ([`seed_fingerprint`]) before use.
pub fn combine_seed(pieces: &[SeedPiece]) -> Result<[u8; 32], String> {
	if pieces.len() < 2 {
		return Err("need at least 2 seed pieces".into());
	}
	for (i, p) in pieces.iter().enumerate() {
		if p.number == 0 || pieces[..i].iter().any(|q| q.number == p.number) {
			return Err("seed pieces must have distinct numbers".into());
		}
	}
	let mut seed = [0u8; 32];
	for (i, p) in pieces.iter().enumerate() {
		// Lagrange basis at x = 0.
		let mut basis = 1u8;
		for (j, q) in pieces.iter().enumerate() {
			if i != j {
				basis = gf_mul(basis, gf_mul(q.number, gf_inv(q.number ^ p.number)));
			}
		}
		for (byte, out) in seed.iter_mut().enumerate() {
			*out ^= gf_mul(p.bytes[byte], basis);
		}
	}
	Ok(seed)
}

/// A public check value for the master seed, so a ceremony can confirm it rebuilt the right one.
pub fn seed_fingerprint(seed: &[u8; 32]) -> String {
	let mut engine = sha256::Hash::engine();
	engine.input(b"ldk-server-mpc/seed-fingerprint/v1");
	engine.input(seed);
	sha256::Hash::from_engine(engine).to_byte_array()[..8].as_hex().to_string()
}

/// Helpers shared by this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_util {
	use std::thread;
	use std::time::Duration;

	use bitcoin::secp256k1::rand::{thread_rng, RngCore};

	use super::*;
	use crate::tdh2::{Tdh2Key, TwoParty};
	use crate::transport::ChannelTransport;

	pub fn tdh2_keys() -> (Tdh2Key, Tdh2Key) {
		let (ta, tb) = ChannelTransport::pair(Duration::from_secs(30));
		let names = ["party-a", "party-b"];
		let b = thread::spawn(move || tdh2::dkg(&names, 1, &TwoParty(&tb)).unwrap());
		let a = tdh2::dkg(&names, 0, &TwoParty(&ta)).unwrap();
		(a, b.join().unwrap())
	}

	pub fn tmp_dir(name: &str) -> PathBuf {
		let mut n = [0u8; 8];
		thread_rng().fill_bytes(&mut n);
		let dir = std::env::temp_dir().join(format!("ldk-mpc-kit-{name}-{}", n.as_hex()));
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	/// A kit store holding one kit of `count` entries from the first commitment number.
	pub fn store_with_kit(kit_id: &KitId, count: u32) -> (KitStore, Tdh2Key, Tdh2Key) {
		let (a, b) = tdh2_keys();
		let dir = tmp_dir("fixture");
		let seg = generate_segment(
			&[0x42u8; 32],
			kit_id,
			&a.public_key,
			INITIAL_COMMITMENT_NUMBER,
			count,
		)
		.unwrap();
		fs::write(dir.join(segment_file_name(kit_id, INITIAL_COMMITMENT_NUMBER)), seg).unwrap();
		(KitStore::open(&dir).unwrap(), a, b)
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::rand::{thread_rng, RngCore};
	use lightning::ln::chan_utils::CounterpartyCommitmentSecrets;

	use super::test_util::{tdh2_keys, tmp_dir};
	use super::*;
	use crate::tdh2::Tdh2Key;

	fn decrypt(a: &Tdh2Key, b: &Tdh2Key, kit: &KitId, idx: u64, rec: &KitRecord) -> [u8; 32] {
		let l = label(kit, idx);
		let pa = a.partial_decrypt(&rec.ciphertext, &l).unwrap();
		let pb = b.partial_decrypt(&rec.ciphertext, &l).unwrap();
		a.combine(&rec.ciphertext, &l, &[pa, pb]).unwrap().try_into().unwrap()
	}

	#[test]
	fn kit_secrets_form_a_bolt3_shachain() {
		let (a, b) = tdh2_keys();
		let master = [0x11u8; 32];
		let kit = [0x22u8; 32];
		let dir = tmp_dir("shachain");
		let seg =
			generate_segment(&master, &kit, &a.public_key, INITIAL_COMMITMENT_NUMBER, 40).unwrap();
		fs::write(dir.join(segment_file_name(&kit, INITIAL_COMMITMENT_NUMBER)), seg).unwrap();
		let store = KitStore::open(&dir).unwrap();
		let secp = Secp256k1::new();

		// The counterparty's own check: LDK's shachain store rejects any secret that does not
		// derive the ones it was given before.
		let mut peer = CounterpartyCommitmentSecrets::new();
		for i in 0..40u64 {
			let idx = INITIAL_COMMITMENT_NUMBER - i;
			let rec = store.record(&kit, idx).unwrap().unwrap();
			let secret = decrypt(&a, &b, &kit, idx, &rec);
			assert_eq!(
				PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap()),
				rec.point
			);
			peer.provide_secret(idx, secret).expect("secret must fit the shachain");
		}
		assert!(store.record(&kit, INITIAL_COMMITMENT_NUMBER - 40).unwrap().is_none());
	}

	#[test]
	fn generation_matches_bolt3_appendix_d() {
		// BOLT 3 Appendix D, "generate_from_seed FF final node" and "alternate bits 1".
		let seed = [0xffu8; 32];
		assert_eq!(
			chan_utils::build_commitment_secret(&seed, 281474976710655).as_hex().to_string(),
			"7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"
		);
		assert_eq!(
			chan_utils::build_commitment_secret(&seed, 0xaaaaaaaaaaa).as_hex().to_string(),
			"56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"
		);
	}

	#[test]
	fn a_ciphertext_cannot_stand_in_for_another_index() {
		let (a, b) = tdh2_keys();
		let kit = [0x33u8; 32];
		let dir = tmp_dir("swap");
		let seg = generate_segment(&[1u8; 32], &kit, &a.public_key, INITIAL_COMMITMENT_NUMBER, 4)
			.unwrap();
		fs::write(dir.join(segment_file_name(&kit, INITIAL_COMMITMENT_NUMBER)), seg).unwrap();
		let store = KitStore::open(&dir).unwrap();
		let future = store.record(&kit, INITIAL_COMMITMENT_NUMBER - 3).unwrap().unwrap();
		// A party asked to release the oldest secret is handed the ciphertext of a future one.
		let l = label(&kit, INITIAL_COMMITMENT_NUMBER);
		assert!(b.partial_decrypt(&future.ciphertext, &l).is_err());
		assert!(a.partial_decrypt(&future.ciphertext, &l).is_err());
	}

	#[test]
	fn segments_extend_a_kit() {
		let (a, _) = tdh2_keys();
		let kit = [0x44u8; 32];
		let dir = tmp_dir("refill");
		let top = INITIAL_COMMITMENT_NUMBER;
		let store = KitStore::open(&dir).unwrap();
		assert_eq!(store.remaining(&kit, top).unwrap(), 0);
		let seg = generate_segment(&[1u8; 32], &kit, &a.public_key, top, 10).unwrap();
		fs::write(dir.join(segment_file_name(&kit, top)), seg).unwrap();
		assert_eq!(store.remaining(&kit, top).unwrap(), 10);
		assert_eq!(store.remaining(&kit, top - 7).unwrap(), 3);
		assert!(store.record(&kit, top - 10).unwrap().is_none());

		// The refill ceremony adds the next segment; the store finds it without a restart.
		let seg = generate_segment(&[1u8; 32], &kit, &a.public_key, top - 10, 5).unwrap();
		fs::write(dir.join(segment_file_name(&kit, top - 10)), seg).unwrap();
		assert!(store.record(&kit, top - 12).unwrap().is_some());
		assert_eq!(store.remaining(&kit, top - 7).unwrap(), 8);
		assert_eq!(store.public_key_id(&kit, top).unwrap(), Some(public_key_id(&a.public_key)));
	}

	#[test]
	fn a_kit_serves_one_channel() {
		let (a, _) = tdh2_keys();
		let dir = tmp_dir("bind");
		let top = INITIAL_COMMITMENT_NUMBER;
		for kit in [[1u8; 32], [2u8; 32]] {
			let seg = generate_segment(&[9u8; 32], &kit, &a.public_key, top, 2).unwrap();
			fs::write(dir.join(segment_file_name(&kit, top)), seg).unwrap();
		}
		let store = KitStore::open(&dir).unwrap();
		assert_eq!(store.unbound_count().unwrap(), 2);
		let first = store.bind_unbound(&[0xaa; 32], &a.public_key).unwrap();
		assert_eq!(store.bind_unbound(&[0xaa; 32], &a.public_key).unwrap(), first);
		let second = store.bind_unbound(&[0xbb; 32], &a.public_key).unwrap();
		assert_ne!(first, second);
		assert!(store.bind_unbound(&[0xcc; 32], &a.public_key).is_err(), "pool is empty");
		assert!(store.bind(&first, &[0xbb; 32]).is_err());
		store.bind(&first, &[0xaa; 32]).unwrap();
		assert!(store.bind(&[7u8; 32], &[0xaa; 32]).is_err(), "unknown kit");
		// Kits made for another TDH2 key are never handed out.
		assert!(KitStore::open(&dir).unwrap().bind_unbound(&[0xdd; 32], b"other key").is_err());
	}

	#[test]
	fn seed_pieces_rebuild_the_seed() {
		let mut seed = [0u8; 32];
		thread_rng().fill_bytes(&mut seed);
		let pieces = split_seed(&seed, 3, 5, |b| thread_rng().fill_bytes(b)).unwrap();
		assert_eq!(pieces.len(), 5);
		for subset in [[0, 1, 2], [4, 2, 0], [1, 3, 4]] {
			let chosen: Vec<SeedPiece> = subset.iter().map(|i| pieces[*i].clone()).collect();
			assert_eq!(combine_seed(&chosen).unwrap(), seed);
		}
		assert_eq!(combine_seed(&pieces).unwrap(), seed);
		// Two of three-needed pieces rebuild something else.
		assert_ne!(combine_seed(&pieces[..2]).unwrap(), seed);
		assert_ne!(seed_fingerprint(&combine_seed(&pieces[..2]).unwrap()), seed_fingerprint(&seed));
		assert!(combine_seed(&[pieces[0].clone(), pieces[0].clone()]).is_err());
		let hex = pieces[3].to_hex();
		assert!(SeedPiece::from_hex(&hex).unwrap() == pieces[3]);
		assert!(split_seed(&seed, 1, 3, |_| {}).is_err());
		assert!(split_seed(&seed, 4, 3, |_| {}).is_err());
	}

	#[test]
	fn gf256_inverse() {
		for a in 1..=255u8 {
			assert_eq!(gf_mul(a, gf_inv(a)), 1);
		}
	}
}
