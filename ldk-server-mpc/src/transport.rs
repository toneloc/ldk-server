//! Transports for the cb-mpc protocol messages between the two parties.

use std::io::{Read, Write};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use crate::cbmpc::{Transport, TransportError};

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

/// A framed transport over an established (optionally PSK-secured) connection to the other
/// party.
///
/// The protocol library drives the connection strictly in lock-step (send/recv alternate), so a
/// single mutex-protected connection is sufficient.
pub struct TcpTransport {
	conn: Mutex<crate::secure::Conn>,
}

impl TcpTransport {
	pub fn new(conn: crate::secure::Conn, timeout: Duration) -> std::io::Result<Self> {
		conn.set_timeouts(timeout)?;
		Ok(TcpTransport { conn: Mutex::new(conn) })
	}

	pub fn into_inner(self) -> crate::secure::Conn {
		self.conn.into_inner().unwrap_or_else(|e| e.into_inner())
	}
}

impl Transport for TcpTransport {
	fn send(&self, msg: &[u8]) -> Result<(), TransportError> {
		let mut c = self.conn.lock().map_err(|_| TransportError("poisoned".into()))?;
		c.write_frame(msg).map_err(Into::into)
	}

	fn recv(&self) -> Result<Vec<u8>, TransportError> {
		let mut c = self.conn.lock().map_err(|_| TransportError("poisoned".into()))?;
		c.read_frame().map_err(Into::into)
	}
}

/// In-process transport pair backed by channels. Used by tests and benchmarks that run
/// both parties in one process (on separate threads).
pub struct ChannelTransport {
	tx: Sender<Vec<u8>>,
	rx: Mutex<Receiver<Vec<u8>>>,
	timeout: Duration,
}

impl ChannelTransport {
	pub fn pair(timeout: Duration) -> (ChannelTransport, ChannelTransport) {
		let (a_tx, b_rx) = channel();
		let (b_tx, a_rx) = channel();
		(
			ChannelTransport { tx: a_tx, rx: Mutex::new(a_rx), timeout },
			ChannelTransport { tx: b_tx, rx: Mutex::new(b_rx), timeout },
		)
	}
}

impl Transport for ChannelTransport {
	fn send(&self, msg: &[u8]) -> Result<(), TransportError> {
		self.tx.send(msg.to_vec()).map_err(|_| TransportError("peer dropped".into()))
	}

	fn recv(&self) -> Result<Vec<u8>, TransportError> {
		let rx = self.rx.lock().map_err(|_| TransportError("poisoned".into()))?;
		rx.recv_timeout(self.timeout).map_err(|e| TransportError(e.to_string()))
	}
}
