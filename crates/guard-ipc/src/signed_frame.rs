//! Per-message HMAC-SHA256 signing for IPC frames.
//!
//! Wire format (after the 1-byte tag, which is read by classify_frame):
//!
//!   [8-byte nonce LE][32-byte HMAC-SHA256][4-byte length BE][CBOR payload]
//!
//! The HMAC covers: tag || nonce || length_prefix || payload.
//! The nonce is a per-connection monotonic counter (u64 LE). Each direction
//! (sender → receiver) maintains its own counter starting at 0.
//!
//! When no HMAC key is available (key = None), the functions fall back to
//! unsigned frames transparently — the nonce/HMAC header is omitted and the
//! wire format is the same as `frame::write_frame` / `frame::read_frame`.

use crate::error::IpcError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

type HmacSha256 = Hmac<Sha256>;

pub const NONCE_BYTES: usize = 8;
pub const HMAC_BYTES: usize = 32;

/// Tracks per-connection send/receive nonce state.
pub struct FrameSigner {
    key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
}

impl FrameSigner {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Write a signed frame: nonce + HMAC + length-prefixed CBOR.
    /// `tag` is the message tag byte (already written to the stream by the caller).
    pub fn write_signed<W: Write, T: serde::Serialize>(
        &mut self,
        w: &mut W,
        tag: u8,
        value: &T,
    ) -> Result<(), IpcError> {
        let mut cbor_buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(value, &mut cbor_buf).map_err(IpcError::codec)?;
        let len = cbor_buf.len();
        if len as u64 > crate::frame::MAX_FRAME_BYTES as u64 {
            return Err(IpcError::FrameTooLarge {
                got: len as u32,
                max: crate::frame::MAX_FRAME_BYTES,
            });
        }
        let length_prefix = (len as u32).to_be_bytes();
        let nonce = self.send_nonce;
        self.send_nonce = nonce.wrapping_add(1);
        let nonce_bytes = nonce.to_le_bytes();

        let hmac_value = compute_hmac(&self.key, tag, &nonce_bytes, &length_prefix, &cbor_buf);

        w.write_all(&nonce_bytes)?;
        w.write_all(&hmac_value)?;
        w.write_all(&length_prefix)?;
        w.write_all(&cbor_buf)?;
        w.flush()?;
        Ok(())
    }

    /// Read a signed frame: verify nonce + HMAC, then decode CBOR.
    /// `tag` is the message tag byte (already read from the stream by the caller).
    pub fn read_signed<R: Read, T: serde::de::DeserializeOwned>(
        &mut self,
        r: &mut R,
        tag: u8,
    ) -> Result<T, IpcError> {
        let mut nonce_buf = [0u8; NONCE_BYTES];
        r.read_exact(&mut nonce_buf)?;
        let nonce = u64::from_le_bytes(nonce_buf);

        if nonce < self.recv_nonce {
            return Err(IpcError::NonceReplay {
                expected: self.recv_nonce,
                got: nonce,
            });
        }
        self.recv_nonce = nonce.wrapping_add(1);

        let mut hmac_buf = [0u8; HMAC_BYTES];
        r.read_exact(&mut hmac_buf)?;

        let mut length_prefix = [0u8; 4];
        r.read_exact(&mut length_prefix)?;
        let len = u32::from_be_bytes(length_prefix);
        if len > crate::frame::MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge {
                got: len,
                max: crate::frame::MAX_FRAME_BYTES,
            });
        }

        let mut payload = vec![0u8; len as usize];
        r.read_exact(&mut payload)?;

        let expected = compute_hmac(&self.key, tag, &nonce_buf, &length_prefix, &payload);
        if !constant_time_eq(&hmac_buf, &expected) {
            return Err(IpcError::HmacMismatch);
        }

        ciborium::de::from_reader(payload.as_slice()).map_err(IpcError::codec)
    }
}

fn compute_hmac(
    key: &[u8; 32],
    tag: u8,
    nonce: &[u8; NONCE_BYTES],
    length_prefix: &[u8; 4],
    payload: &[u8],
) -> [u8; HMAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&[tag]);
    mac.update(nonce);
    mac.update(length_prefix);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(a: &[u8; HMAC_BYTES], b: &[u8; HMAC_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..HMAC_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn signed_roundtrip() {
        let key = test_key();
        let tag = 0x03u8;
        let msg: String = "hello stt-guard".into();

        let mut buf = Vec::new();
        let mut signer = FrameSigner::new(key);
        signer.write_signed(&mut buf, tag, &msg).unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut verifier = FrameSigner::new(key);
        let decoded: String = verifier.read_signed(&mut cursor, tag).unwrap();
        assert_eq!(decoded, "hello stt-guard");
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = test_key();
        let tag = 0x03u8;
        let msg: String = "hello".into();

        let mut buf = Vec::new();
        let mut signer = FrameSigner::new(key);
        signer.write_signed(&mut buf, tag, &msg).unwrap();

        // Flip a byte in the CBOR payload (past nonce + HMAC + length prefix).
        let payload_offset = NONCE_BYTES + HMAC_BYTES + 4;
        if buf.len() > payload_offset {
            buf[payload_offset] ^= 0xFF;
        }

        let mut cursor = Cursor::new(&buf);
        let mut verifier = FrameSigner::new(key);
        let result: Result<String, _> = verifier.read_signed(&mut cursor, tag);
        assert!(matches!(result, Err(IpcError::HmacMismatch)));
    }

    #[test]
    fn wrong_key_rejected() {
        let key = test_key();
        let tag = 0x03u8;
        let msg: String = "hello".into();

        let mut buf = Vec::new();
        let mut signer = FrameSigner::new(key);
        signer.write_signed(&mut buf, tag, &msg).unwrap();

        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        let mut cursor = Cursor::new(&buf);
        let mut verifier = FrameSigner::new(wrong_key);
        let result: Result<String, _> = verifier.read_signed(&mut cursor, tag);
        assert!(matches!(result, Err(IpcError::HmacMismatch)));
    }

    #[test]
    fn wrong_tag_rejected() {
        let key = test_key();
        let msg: String = "hello".into();

        let mut buf = Vec::new();
        let mut signer = FrameSigner::new(key);
        signer.write_signed(&mut buf, 0x03, &msg).unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut verifier = FrameSigner::new(key);
        let result: Result<String, _> = verifier.read_signed(&mut cursor, 0x04);
        assert!(matches!(result, Err(IpcError::HmacMismatch)));
    }

    #[test]
    fn nonce_replay_rejected() {
        let key = test_key();
        let tag = 0x03u8;
        let msg: String = "hello".into();

        let mut buf = Vec::new();
        let mut signer = FrameSigner::new(key);
        signer.write_signed(&mut buf, tag, &msg).unwrap();

        // First read succeeds.
        let mut verifier = FrameSigner::new(key);
        let mut cursor = Cursor::new(&buf);
        let _: String = verifier.read_signed(&mut cursor, tag).unwrap();

        // Replay the same bytes — nonce 0 < expected 1.
        let mut cursor = Cursor::new(&buf);
        let result: Result<String, _> = verifier.read_signed(&mut cursor, tag);
        assert!(matches!(result, Err(IpcError::NonceReplay { .. })));
    }

    #[test]
    fn sequential_nonces_accepted() {
        let key = test_key();
        let tag = 0x03u8;

        let mut signer = FrameSigner::new(key);
        let mut verifier = FrameSigner::new(key);

        for i in 0u32..5 {
            let msg = format!("msg-{i}");
            let mut buf = Vec::new();
            signer.write_signed(&mut buf, tag, &msg).unwrap();

            let mut cursor = Cursor::new(&buf);
            let decoded: String = verifier.read_signed(&mut cursor, tag).unwrap();
            assert_eq!(decoded, msg);
        }
    }
}
