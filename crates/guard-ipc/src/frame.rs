//! Length-prefixed CBOR framing.
//!
//! Wire format: 4-byte big-endian payload length, followed by exactly that many
//! CBOR bytes encoding T.
//!
//! `MAX_FRAME_BYTES` bounds the per-message size; the receiver REJECTS oversized
//! length prefixes before allocating any buffer.

use crate::error::IpcError;
use std::io::{Read, Write};

pub const MAX_FRAME_BYTES: u32 = 64 * 1024;
pub const MAX_SNAPSHOT_FRAME_BYTES: u32 = 4 * 1024 * 1024;
pub const FRAME_LENGTH_BYTES: usize = 4;

/// Write a value using the default frame-size limit.
///
/// # Errors
///
/// Returns an IPC error if serialization fails, the frame exceeds the default
/// limit, or the writer fails.
pub fn write_frame<W: Write, T: serde::Serialize>(w: &mut W, value: &T) -> Result<(), IpcError> {
    write_frame_with_limit(w, value, MAX_FRAME_BYTES)
}

/// Write a value using a caller-provided frame-size limit.
///
/// # Errors
///
/// Returns an IPC error if serialization fails, the frame exceeds
/// `max_frame_bytes`, or the writer fails.
pub fn write_frame_with_limit<W: Write, T: serde::Serialize>(
    w: &mut W,
    value: &T,
    max_frame_bytes: u32,
) -> Result<(), IpcError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut buf).map_err(IpcError::codec)?;
    let len = buf.len();
    let max_frame_len = usize::try_from(max_frame_bytes).map_err(|_| IpcError::FrameTooLarge {
        got: u32::MAX,
        max: max_frame_bytes,
    })?;

    if len > max_frame_len {
        return Err(IpcError::FrameTooLarge {
            got: u32::try_from(len).unwrap_or(u32::MAX),
            max: max_frame_bytes,
        });
    }
    let frame_len = u32::try_from(len).map_err(|_| IpcError::FrameTooLarge {
        got: u32::MAX,
        max: max_frame_bytes,
    })?;
    let prefix: [u8; 4] = frame_len.to_be_bytes();
    w.write_all(&prefix)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read a value using the default frame-size limit.
///
/// # Errors
///
/// Returns an IPC error if the frame is too large, I/O fails, or decoding fails.
pub fn read_frame<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, IpcError> {
    read_frame_with_limit(r, MAX_FRAME_BYTES)
}

/// Read a value using a caller-provided frame-size limit.
///
/// # Errors
///
/// Returns an IPC error if the frame is too large, I/O fails, or decoding fails.
pub fn read_frame_with_limit<R: Read, T: serde::de::DeserializeOwned>(
    r: &mut R,
    max_frame_bytes: u32,
) -> Result<T, IpcError> {
    let mut prefix = [0u8; FRAME_LENGTH_BYTES];
    r.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix);
    // BOUNDS CHECK before any allocation — mitigates DoS via oversized length prefix.
    if len > max_frame_bytes {
        return Err(IpcError::FrameTooLarge {
            got: len,
            max: max_frame_bytes,
        });
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    ciborium::de::from_reader(payload.as_slice()).map_err(IpcError::codec)
}
