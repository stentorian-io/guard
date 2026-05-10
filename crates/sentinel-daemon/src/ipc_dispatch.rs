//! Tagged-frame IPC dispatch.
//!
//! All Phase 2 messages on the wire are: `[1-byte MessageTag][length-prefixed CBOR body]`.
//!
//! Phase 1 `RegisterRoot` is FROZEN at `[length-prefixed CBOR body]` (no tag byte).
//!
//! Distinguishing the two: the legacy frame's length prefix is a 4-byte big-endian
//! integer per `sentinel-ipc/src/frame.rs`. The frame size is bounded by
//! `MAX_FRAME_BYTES = 64 * 1024 = 0x10000`, so a valid legacy length-prefix high
//! byte is ALWAYS 0x00. Any other high byte is either a Phase 2 tag
//! (0x02..=0x08) or a protocol violation.
//!
//! WARNING-06 fix (Phase 2 review): the previous comment claimed any byte in
//! 0x00..=0x01 ∪ 0x09..=0xff was "legacy length-prefix high byte" — but a
//! valid legacy frame has only 0x00 in the high byte (0x01 already implies
//! a 16+ MiB body, far above MAX_FRAME_BYTES). The dispatcher now treats:
//!   - 0x02..=0x12            → tagged Phase 2/3/07/v0.3 message
//!                              (0x0E..=0x11 = ListRules/ListTrust/IsTrusted/DeleteInstallArtifacts, plan 07-01)
//!                              (0x12 = DenyNotify, v0.3 D-39)
//!   - 0x00                   → legacy RegisterRoot (Phase 1)
//!   - everything else        → protocol violation (rejected immediately)
//!
//! This catches scribble traffic and stops downstream code from spending
//! cycles reading 3 more bytes for an obviously-invalid length prefix
//! before failing.

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
    EnvNotPropagatedGap = 0x08,
    // Phase 3 — new IPC tag bytes (D-69 + research recommendations):
    Status = 0x09,
    PromptChannelInit = 0x0A,
    InsertUserRule = 0x0B,
    ReadInstallArtifacts = 0x0C,
    BaselineCommit = 0x0D,
    // Phase 07 plan 01 — management-IPC family (additive at IPC_SCHEMA_V3):
    ListRules = 0x0E,
    ListTrust = 0x0F,
    IsTrusted = 0x10,
    DeleteInstallArtifacts = 0x11,
    // v0.3 — D-39 deny-notify IPC:
    DenyNotify = 0x12,
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
            0x08 => Some(Self::EnvNotPropagatedGap),
            // Phase 3:
            0x09 => Some(Self::Status),
            0x0A => Some(Self::PromptChannelInit),
            0x0B => Some(Self::InsertUserRule),
            0x0C => Some(Self::ReadInstallArtifacts),
            0x0D => Some(Self::BaselineCommit),
            // Phase 07 plan 01:
            0x0E => Some(Self::ListRules),
            0x0F => Some(Self::ListTrust),
            0x10 => Some(Self::IsTrusted),
            0x11 => Some(Self::DeleteInstallArtifacts),
            // v0.3 — D-39:
            0x12 => Some(Self::DenyNotify),
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
    /// FIRST byte of a 4-byte length prefix (always 0x00 in valid legacy
    /// frames per MAX_FRAME_BYTES = 64 KiB) and read the rest of the frame
    /// as length-prefixed CBOR (RegisterRoot).
    LegacyUntagged { first_length_byte: u8 },
    /// Phase 2: caller should read a length-prefixed CBOR body of this type.
    Tagged(MessageTag),
}

/// Peek the first byte to decide framing kind. Reads exactly 1 byte from the
/// stream — caller must continue with the appropriate read path.
///
/// WARNING-06: only 0x00 (legacy length-prefix high byte) and 0x02..=0x12
/// (Phase 2/3/v0.3 tags) are valid first bytes. Anything else is a protocol
/// violation (invalid length prefix or unknown tag). Rejecting at this
/// stage prevents the legacy handler from spending three more
/// `read_exact(1)` syscalls on garbage frames before failing.
pub fn classify_frame(stream: &mut UnixStream) -> Result<FrameKind, DispatchError> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first)?;
    let b = first[0];
    if let Some(tag) = MessageTag::from_byte(b) {
        return Ok(FrameKind::Tagged(tag));
    }
    if b == 0x00 {
        // Phase 1 legacy length-prefixed frame's high byte (always 0x00 for
        // any frame ≤ MAX_FRAME_BYTES = 64 KiB).
        return Ok(FrameKind::LegacyUntagged {
            first_length_byte: b,
        });
    }
    // Anything else: not a valid Phase 2 tag and not a valid legacy
    // length-prefix high byte. Reject as a protocol violation.
    Err(DispatchError::UnknownTag(b))
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
            MessageTag::EnvNotPropagatedGap,
            // Phase 3:
            MessageTag::Status,
            MessageTag::PromptChannelInit,
            MessageTag::InsertUserRule,
            MessageTag::ReadInstallArtifacts,
            MessageTag::BaselineCommit,
            // Phase 07 plan 01:
            MessageTag::ListRules,
            MessageTag::ListTrust,
            MessageTag::IsTrusted,
            MessageTag::DeleteInstallArtifacts,
            // v0.3 D-39:
            MessageTag::DenyNotify,
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
        // 0x13+ — unassigned tag space (0x12 = DenyNotify, v0.3 D-39).
        assert!(MessageTag::from_byte(0x13).is_none());
        assert!(MessageTag::from_byte(0xff).is_none());
    }

    #[test]
    fn tag_byte_values_are_stable() {
        // Wire-stable values — never renumber once shipped.
        // Phase 2:
        assert_eq!(MessageTag::PrepareSnapshot.as_byte(), 0x02);
        assert_eq!(MessageTag::ForkEvent.as_byte(), 0x03);
        assert_eq!(MessageTag::ExecEvent.as_byte(), 0x04);
        assert_eq!(MessageTag::DylibLoaded.as_byte(), 0x05);
        assert_eq!(MessageTag::Resolve.as_byte(), 0x06);
        assert_eq!(MessageTag::TrustPolicy.as_byte(), 0x07);
        assert_eq!(MessageTag::EnvNotPropagatedGap.as_byte(), 0x08);
        // Phase 3:
        assert_eq!(MessageTag::Status.as_byte(), 0x09);
        assert_eq!(MessageTag::PromptChannelInit.as_byte(), 0x0A);
        assert_eq!(MessageTag::InsertUserRule.as_byte(), 0x0B);
        assert_eq!(MessageTag::ReadInstallArtifacts.as_byte(), 0x0C);
        assert_eq!(MessageTag::BaselineCommit.as_byte(), 0x0D);
        // Phase 07 plan 01:
        assert_eq!(MessageTag::ListRules as u8, 0x0E);
        assert_eq!(MessageTag::ListTrust as u8, 0x0F);
        assert_eq!(MessageTag::IsTrusted as u8, 0x10);
        assert_eq!(MessageTag::DeleteInstallArtifacts as u8, 0x11);
        // from_byte round-trips for all Phase 3 tags:
        assert!(matches!(MessageTag::from_byte(0x09), Some(MessageTag::Status)));
        assert!(matches!(
            MessageTag::from_byte(0x0A),
            Some(MessageTag::PromptChannelInit)
        ));
        assert!(matches!(
            MessageTag::from_byte(0x0B),
            Some(MessageTag::InsertUserRule)
        ));
        assert!(matches!(
            MessageTag::from_byte(0x0C),
            Some(MessageTag::ReadInstallArtifacts)
        ));
        assert!(matches!(
            MessageTag::from_byte(0x0D),
            Some(MessageTag::BaselineCommit)
        ));
        // Phase 07 plan 01:
        assert_eq!(MessageTag::from_byte(0x0E), Some(MessageTag::ListRules));
        assert_eq!(MessageTag::from_byte(0x0F), Some(MessageTag::ListTrust));
        assert_eq!(MessageTag::from_byte(0x10), Some(MessageTag::IsTrusted));
        assert_eq!(
            MessageTag::from_byte(0x11),
            Some(MessageTag::DeleteInstallArtifacts)
        );
        // v0.3 D-39:
        assert_eq!(MessageTag::DenyNotify as u8, 0x12);
        assert_eq!(MessageTag::from_byte(0x12), Some(MessageTag::DenyNotify));
        // 0x13 is unassigned — must return None:
        assert_eq!(MessageTag::from_byte(0x13), None);
    }
}
