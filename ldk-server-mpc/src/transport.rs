//! Framing for the party links, and an in-process transport for tests and benchmarks.

use std::io::{Read, Write};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use crate::cbmpc::TransportError;

/// Maximum size of a single framed protocol message (defensive bound).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Writes one length-prefixed frame (`u32` big-endian length followed by payload).
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
	if payload.len() > MAX_FRAME_LEN {
		return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"));
	}
	w.write_all(&(payload.len() as u32).to_be_bytes())?;
	w.write_all(payload)?;
	w.flush()
}

/// Reads one length-prefixed frame.
pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
	let mut len = [0u8; 4];
	r.read_exact(&mut len)?;
	let len = u32::from_be_bytes(len) as usize;
	if len > MAX_FRAME_LEN {
		return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
	}
	let mut buf = vec![0u8; len];
	r.read_exact(&mut buf)?;
	Ok(buf)
}

/// One party's end of a link to another: where it sends and where it receives.
type LocalLink = (Sender<Vec<u8>>, Mutex<Receiver<Vec<u8>>>);

/// In-process transport for an `n`-party session: every pair of parties is joined by a pair
/// of channels. Used by tests and benchmarks that run all parties in one process.
pub struct LocalMesh {
	/// `links[peer]` is `None` for this party's own index.
	links: Vec<Option<LocalLink>>,
	timeout: Duration,
}

impl LocalMesh {
	/// One transport per party, in party order.
	pub fn new(n: usize, timeout: Duration) -> Vec<LocalMesh> {
		let mut parties: Vec<LocalMesh> =
			(0..n).map(|_| LocalMesh { links: (0..n).map(|_| None).collect(), timeout }).collect();
		for i in 0..n {
			for j in (i + 1)..n {
				let (i_tx, j_rx) = channel();
				let (j_tx, i_rx) = channel();
				parties[i].links[j] = Some((i_tx, Mutex::new(i_rx)));
				parties[j].links[i] = Some((j_tx, Mutex::new(j_rx)));
			}
		}
		parties
	}

	fn link(&self, peer: usize) -> Result<&LocalLink, TransportError> {
		self.links
			.get(peer)
			.and_then(|l| l.as_ref())
			.ok_or_else(|| TransportError(format!("no link to party {peer}")))
	}
}

impl crate::mp::MpTransport for LocalMesh {
	fn send(&self, peer: usize, msg: &[u8]) -> Result<(), TransportError> {
		self.link(peer)?.0.send(msg.to_vec()).map_err(|_| TransportError("peer dropped".into()))
	}

	fn recv(&self, peer: usize) -> Result<Vec<u8>, TransportError> {
		let rx = self.link(peer)?.1.lock().map_err(|_| TransportError("poisoned".into()))?;
		rx.recv_timeout(self.timeout).map_err(|e| TransportError(e.to_string()))
	}
}
