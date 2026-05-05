//! Length-prefixed CBOR framing.
//!
//! Wire format: 4-byte big-endian payload length, followed by exactly that many
//! CBOR bytes encoding T.
//!
//! MAX_FRAME_BYTES bounds the per-message size; the receiver REJECTS oversized
//! length prefixes before allocating any buffer (security threat T-01-04-01).

use crate::error::IpcError;
use std::io::{Read, Write};

pub const MAX_FRAME_BYTES: u32 = 64 * 1024;
pub const FRAME_LENGTH_BYTES: usize = 4;

pub fn write_frame<W: Write, T: serde::Serialize>(w: &mut W, value: &T) -> Result<(), IpcError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut buf).map_err(IpcError::codec)?;
    let len = buf.len();
    if len as u64 > MAX_FRAME_BYTES as u64 {
        return Err(IpcError::FrameTooLarge { got: len as u32, max: MAX_FRAME_BYTES });
    }
    let prefix: [u8; 4] = (len as u32).to_be_bytes();
    w.write_all(&prefix)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, IpcError> {
    let mut prefix = [0u8; FRAME_LENGTH_BYTES];
    r.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix);
    // BOUNDS CHECK before any allocation — mitigates T-01-04-01 (DoS via oversized length prefix).
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge { got: len, max: MAX_FRAME_BYTES });
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    ciborium::de::from_reader(payload.as_slice()).map_err(IpcError::codec)
}
