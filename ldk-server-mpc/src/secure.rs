//! Authenticated, encrypted framing over TCP for the party links.
//!
//! Both ends share a 32-byte pre-shared key (PSK). A connection starts with a handshake:
//! each side sends a random 32-byte nonce and an ephemeral X25519 public key; both derive
//! session keys with HKDF-SHA256 from the X25519 shared secret and the PSK, bound to both
//! nonces. Every frame is then AES-256-GCM sealed with a per-direction counter nonce. Without
//! the PSK a peer cannot produce or read any frame, so the first frame authenticates both
//! sides; the ephemeral agreement gives forward secrecy.
//!
//! The PSK files are generated on first start with `0600` permissions and must be copied to
//! the other end out of band. Two different keys are used: one between LDK Server and
//! Party A, one between Party A and Party B.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use crate::transport::{read_frame, write_frame, MAX_FRAME_LEN};

const MAGIC: &[u8; 8] = b"LDKMPC01";
const TAG_LEN: usize = 16;

/// Loads a 32-byte key file, or creates it with fresh randomness if it does not exist.
pub fn load_or_create_key_file(path: &Path) -> io::Result<[u8; 32]> {
	match fs::read(path) {
		Ok(bytes) if bytes.len() == 32 => Ok(bytes.try_into().unwrap()),
		Ok(_) => Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("{} must be 32 bytes", path.display()),
		)),
		Err(e) if e.kind() == io::ErrorKind::NotFound => {
			let mut key = [0u8; 32];
			SystemRandom::new().fill(&mut key).map_err(|_| io::Error::other("rng failure"))?;
			if let Some(parent) = path.parent() {
				fs::create_dir_all(parent)?;
			}
			let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				f.set_permissions(fs::Permissions::from_mode(0o600))?;
			}
			f.write_all(&key)?;
			f.sync_all()?;
			Ok(key)
		},
		Err(e) => Err(e),
	}
}

struct Direction {
	key: LessSafeKey,
	counter: u64,
}

impl Direction {
	fn new(key_bytes: &[u8; 32]) -> Self {
		let key =
			LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key_bytes).expect("valid key length"));
		Direction { key, counter: 0 }
	}

	fn next_nonce(&mut self) -> io::Result<Nonce> {
		let n = self.counter;
		self.counter =
			self.counter.checked_add(1).ok_or_else(|| io::Error::other("nonce exhausted"))?;
		let mut bytes = [0u8; 12];
		bytes[4..].copy_from_slice(&n.to_be_bytes());
		Ok(Nonce::assume_unique_for_key(bytes))
	}
}

struct HkdfLen(usize);

impl ring::hkdf::KeyType for HkdfLen {
	fn len(&self) -> usize {
		self.0
	}
}

/// An encrypted, authenticated connection.
pub struct SecureStream {
	stream: TcpStream,
	send: Direction,
	recv: Direction,
}

impl SecureStream {
	/// Runs the handshake. `is_initiator` decides key direction labels only; both sides run
	/// the same steps.
	pub fn handshake(
		mut stream: TcpStream, psk: &[u8; 32], is_initiator: bool,
	) -> io::Result<Self> {
		let rng = SystemRandom::new();
		let mut my_nonce = [0u8; 32];
		rng.fill(&mut my_nonce).map_err(|_| io::Error::other("rng failure"))?;
		let my_priv = EphemeralPrivateKey::generate(&X25519, &rng)
			.map_err(|_| io::Error::other("x25519 keygen"))?;
		let my_pub = my_priv.compute_public_key().map_err(|_| io::Error::other("x25519 pubkey"))?;

		let mut hello = Vec::with_capacity(8 + 32 + 32);
		hello.extend_from_slice(MAGIC);
		hello.extend_from_slice(&my_nonce);
		hello.extend_from_slice(my_pub.as_ref());
		stream.write_all(&hello)?;
		stream.flush()?;

		let mut their_hello = [0u8; 8 + 32 + 32];
		stream.read_exact(&mut their_hello)?;
		if &their_hello[..8] != MAGIC {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"peer did not speak the secure protocol",
			));
		}
		let their_nonce: [u8; 32] = their_hello[8..40].try_into().unwrap();
		let their_pub = UnparsedPublicKey::new(&X25519, their_hello[40..72].to_vec());

		// Order the transcript deterministically so both sides derive the same keys.
		let (first_nonce, second_nonce) =
			if is_initiator { (my_nonce, their_nonce) } else { (their_nonce, my_nonce) };
		let mut salt_input = Vec::with_capacity(64);
		salt_input.extend_from_slice(&first_nonce);
		salt_input.extend_from_slice(&second_nonce);

		let keys: [[u8; 32]; 2] = agree_ephemeral(my_priv, &their_pub, |shared| {
			let mut ikm = Vec::with_capacity(64);
			ikm.extend_from_slice(shared);
			ikm.extend_from_slice(psk);
			let prk = Salt::new(HKDF_SHA256, &salt_input).extract(&ikm);
			let mut out = [[0u8; 32]; 2];
			for (i, label) in [&b"ldk-mpc i->r"[..], &b"ldk-mpc r->i"[..]].iter().enumerate() {
				let info = [*label];
				let okm = prk.expand(&info, HkdfLen(32)).expect("hkdf expand");
				okm.fill(&mut out[i]).expect("hkdf fill");
			}
			out
		})
		.map_err(|_| io::Error::other("x25519 agreement"))?;

		let (send_key, recv_key) =
			if is_initiator { (keys[0], keys[1]) } else { (keys[1], keys[0]) };
		let mut secure = SecureStream {
			stream,
			send: Direction::new(&send_key),
			recv: Direction::new(&recv_key),
		};

		// Key confirmation: each side seals an empty frame; a wrong PSK fails here, before any
		// application data is exchanged.
		secure.write_frame(b"")?;
		let confirm = secure.read_frame().map_err(|_| {
			io::Error::new(
				io::ErrorKind::PermissionDenied,
				"peer authentication failed (wrong pre-shared key?)",
			)
		})?;
		if !confirm.is_empty() {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "bad key confirmation"));
		}
		Ok(secure)
	}

	pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
		if payload.len() > MAX_FRAME_LEN {
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
		}
		let nonce = self.send.next_nonce()?;
		let mut buf = payload.to_vec();
		self.send
			.key
			.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
			.map_err(|_| io::Error::other("seal failed"))?;
		write_frame(&mut self.stream, &buf)
	}

	pub fn read_frame(&mut self) -> io::Result<Vec<u8>> {
		let mut buf = read_frame(&mut self.stream)?;
		if buf.len() < TAG_LEN {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "short ciphertext"));
		}
		let nonce = self.recv.next_nonce()?;
		let plain_len = self
			.recv
			.key
			.open_in_place(nonce, Aad::empty(), &mut buf)
			.map_err(|_| {
				io::Error::new(io::ErrorKind::PermissionDenied, "frame authentication failed")
			})?
			.len();
		buf.truncate(plain_len);
		Ok(buf)
	}

	pub fn set_timeouts(&self, timeout: std::time::Duration) -> io::Result<()> {
		self.stream.set_read_timeout(Some(timeout))?;
		self.stream.set_write_timeout(Some(timeout))
	}
}

/// A framed connection that is either plain or PSK-secured.
pub enum Conn {
	Plain(TcpStream),
	Secure(Box<SecureStream>),
}

impl Conn {
	/// Wraps `stream`, running the secure handshake when a PSK is configured.
	pub fn new(stream: TcpStream, psk: Option<&[u8; 32]>, is_initiator: bool) -> io::Result<Self> {
		match psk {
			Some(psk) => {
				Ok(Conn::Secure(Box::new(SecureStream::handshake(stream, psk, is_initiator)?)))
			},
			None => Ok(Conn::Plain(stream)),
		}
	}

	pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
		match self {
			Conn::Plain(s) => write_frame(s, payload),
			Conn::Secure(s) => s.write_frame(payload),
		}
	}

	pub fn read_frame(&mut self) -> io::Result<Vec<u8>> {
		match self {
			Conn::Plain(s) => read_frame(s),
			Conn::Secure(s) => s.read_frame(),
		}
	}

	pub fn set_timeouts(&self, timeout: std::time::Duration) -> io::Result<()> {
		match self {
			Conn::Plain(s) => {
				s.set_read_timeout(Some(timeout))?;
				s.set_write_timeout(Some(timeout))
			},
			Conn::Secure(s) => s.set_timeouts(timeout),
		}
	}
}

// ---------------------------------------------------------------------------
// Encryption at rest
// ---------------------------------------------------------------------------

const ENC_MAGIC: &[u8; 10] = b"LDKMPCENC1";

/// AES-256-GCM encryption of key-share blobs and secrets at rest.
pub struct AtRestKey {
	key: LessSafeKey,
}

impl AtRestKey {
	pub fn new(key: &[u8; 32]) -> Self {
		AtRestKey {
			key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("valid key length")),
		}
	}

	pub fn seal(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
		let mut nonce = [0u8; 12];
		SystemRandom::new().fill(&mut nonce).map_err(|_| io::Error::other("rng failure"))?;
		let mut out = Vec::with_capacity(ENC_MAGIC.len() + 12 + plaintext.len() + TAG_LEN);
		out.extend_from_slice(ENC_MAGIC);
		out.extend_from_slice(&nonce);
		let mut buf = plaintext.to_vec();
		self.key
			.seal_in_place_append_tag(
				Nonce::assume_unique_for_key(nonce),
				Aad::from(ENC_MAGIC),
				&mut buf,
			)
			.map_err(|_| io::Error::other("seal failed"))?;
		out.extend_from_slice(&buf);
		Ok(out)
	}

	pub fn open(&self, data: &[u8]) -> io::Result<Vec<u8>> {
		if data.len() < ENC_MAGIC.len() + 12 + TAG_LEN || &data[..ENC_MAGIC.len()] != ENC_MAGIC {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "not an encrypted blob"));
		}
		let nonce: [u8; 12] = data[ENC_MAGIC.len()..ENC_MAGIC.len() + 12].try_into().unwrap();
		let mut buf = data[ENC_MAGIC.len() + 12..].to_vec();
		let len = self
			.key
			.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(ENC_MAGIC), &mut buf)
			.map_err(|_| {
				io::Error::new(
					io::ErrorKind::PermissionDenied,
					"blob authentication failed (wrong share key?)",
				)
			})?
			.len();
		buf.truncate(len);
		Ok(buf)
	}

	pub fn is_encrypted(data: &[u8]) -> bool {
		data.len() >= ENC_MAGIC.len() && &data[..ENC_MAGIC.len()] == ENC_MAGIC
	}
}

#[cfg(test)]
mod tests {
	use std::net::TcpListener;

	use super::*;

	#[test]
	fn secure_stream_roundtrip_and_psk_mismatch() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		let psk = [7u8; 32];
		let server = std::thread::spawn(move || {
			let (s, _) = listener.accept().unwrap();
			let mut c = SecureStream::handshake(s, &psk, false).unwrap();
			let msg = c.read_frame().unwrap();
			c.write_frame(&[msg.as_slice(), b" back"].concat()).unwrap();
			let (s, _) = listener.accept().unwrap();
			SecureStream::handshake(s, &psk, false).is_err()
		});
		let mut c = SecureStream::handshake(TcpStream::connect(addr).unwrap(), &psk, true).unwrap();
		c.write_frame(b"hello").unwrap();
		assert_eq!(c.read_frame().unwrap(), b"hello back");
		// Wrong PSK on the client side fails key confirmation on both ends.
		let bad = SecureStream::handshake(TcpStream::connect(addr).unwrap(), &[8u8; 32], true);
		assert!(bad.is_err());
		assert!(server.join().unwrap());
	}

	#[test]
	fn at_rest_roundtrip_and_tamper() {
		let k = AtRestKey::new(&[1u8; 32]);
		let sealed = k.seal(b"secret share").unwrap();
		assert!(AtRestKey::is_encrypted(&sealed));
		assert_eq!(k.open(&sealed).unwrap(), b"secret share");
		let mut tampered = sealed.clone();
		let last = tampered.len() - 1;
		tampered[last] ^= 1;
		assert!(k.open(&tampered).is_err());
		assert!(AtRestKey::new(&[2u8; 32]).open(&sealed).is_err());
	}
}
