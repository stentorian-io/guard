//! Tagged-frame IPC dispatch.
//!
//! All Phase 2 messages on the wire are: `[1-byte MessageTag][length-prefixed CBOR body]`.
//!
//! Phase 1 `RegisterRoot` is FROZEN at `[length-prefixed CBOR body]` (no tag byte).
//!
//! Distinguishing the two: the legacy frame's length prefix is a 4-byte big-endian
//! integer per `sentinel-ipc/src/frame.rs`. For any reasonable RegisterRoot CBOR
//! body (≤ ~100 bytes), the first byte of the length prefix is 0x00. The Phase 2
//! tag values are 0x01..=0x07 — non-overlapping with the legacy length prefix's
//! high byte. The dispatcher peeks the first byte before deciding which path to
//! take.

use std::io::Read;
use std::os::unix::net::UnixStream;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageTag {
    PrepareSnapshot = 0x02,
    ForkEvent = 0x03,
    ExecEvent = 0x04,
    DylibLoaded = 0x05,
    Resolve = 0x06,
    TrustPolicy = 0x07,
}

impl MessageTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x02 => Some(Self::PrepareSnapshot),
            0x03 => Some(Self::ForkEvent),
            0x04 => Some(Self::ExecEvent),
            0x05 => Some(Self::DylibLoaded),
            0x06 => Some(Self::Resolve),
            0x07 => Some(Self::TrustPolicy),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("unknown message tag: 0x{0:02x}")]
    UnknownTag(u8),
    #[error("ipc framing: {0}")]
    Frame(String),
}

/// Outcome of `classify_frame` — caller decides which read path to take.
#[derive(Debug)]
pub enum FrameKind {
    /// Phase 1 legacy: caller should treat the already-peeked byte as the
    /// FIRST byte of a 4-byte length prefix and read the rest of the frame
    /// as length-prefixed CBOR (RegisterRoot).
    LegacyUntagged { first_length_byte: u8 },
    /// Phase 2: caller should read a length-prefixed CBOR body of this type.
    Tagged(MessageTag),
}

/// Peek the first byte to decide framing kind. Reads exactly 1 byte from the
/// stream — caller must continue with the appropriate read path.
pub fn classify_frame(stream: &mut UnixStream) -> Result<FrameKind, DispatchError> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first)?;
    if let Some(tag) = MessageTag::from_byte(first[0]) {
        return Ok(FrameKind::Tagged(tag));
    }
    // Phase 1 legacy length-prefixed frame's high byte. Anything outside
    // 0x02..=0x07 is treated as legacy. (0x00 is by far the most common
    // because Phase 1 RegisterRoot bodies are tens of bytes; 0x02..=0x07
    // are captured as tags above. So this branch is reached only for 0x00
    // or 0x01 or 0x08..=0xff, which are valid length-prefix high bytes.
    // 0x01 in the high byte would mean a body ≥ 16 MiB which exceeds
    // MAX_FRAME_BYTES anyway and is rejected downstream.)
    Ok(FrameKind::LegacyUntagged {
        first_length_byte: first[0],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_tag_byte_round_trip() {
        for tag in [
            MessageTag::PrepareSnapshot,
            MessageTag::ForkEvent,
            MessageTag::ExecEvent,
            MessageTag::DylibLoaded,
            MessageTag::Resolve,
            MessageTag::TrustPolicy,
        ] {
            let b = tag.as_byte();
            assert_eq!(MessageTag::from_byte(b), Some(tag));
        }
    }

    #[test]
    fn unknown_byte_yields_no_tag() {
        // 0x00 — typical high byte of a length-prefixed legacy frame.
        assert!(MessageTag::from_byte(0x00).is_none());
        // 0x01 — was reserved for RegisterRoot in early drafts; legacy path now.
        assert!(MessageTag::from_byte(0x01).is_none());
        // 0x08+ — unassigned tag space.
        assert!(MessageTag::from_byte(0x08).is_none());
        assert!(MessageTag::from_byte(0xff).is_none());
    }

    #[test]
    fn tag_byte_values_are_stable() {
        // Wire-stable values — never renumber once shipped.
        assert_eq!(MessageTag::PrepareSnapshot.as_byte(), 0x02);
        assert_eq!(MessageTag::ForkEvent.as_byte(), 0x03);
        assert_eq!(MessageTag::ExecEvent.as_byte(), 0x04);
        assert_eq!(MessageTag::DylibLoaded.as_byte(), 0x05);
        assert_eq!(MessageTag::Resolve.as_byte(), 0x06);
        assert_eq!(MessageTag::TrustPolicy.as_byte(), 0x07);
    }
}
