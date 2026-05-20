//! Tagged-frame IPC dispatch.
//!
//! All v0.2+ messages on the wire are: `[1-byte MessageTag][length-prefixed CBOR body]`.
//!
//! v0.1 `RegisterRoot` is FROZEN at `[length-prefixed CBOR body]` (no tag byte).
//!
//! Distinguishing the two: the legacy frame's length prefix is a 4-byte big-endian
//! integer per `sentinel-ipc/src/frame.rs`. The frame size is bounded by
//! `MAX_FRAME_BYTES = 64 * 1024 = 0x10000`, so a valid legacy length-prefix high
//! byte is ALWAYS 0x00. Any other high byte is either a v0.2+ tag
//! (0x02..=0x08) or a protocol violation.
//!
//! WARNING fix (v0.2 review): the previous comment claimed any byte in
//! 0x00..=0x01 ∪ 0x09..=0xff was "legacy length-prefix high byte" — but a
//! valid legacy frame has only 0x00 in the high byte (0x01 already implies
//! a 16+ MiB body, far above MAX_FRAME_BYTES). The dispatcher now treats:
//!   - 0x02..=0x17            → tagged v0.2/v0.3/v0.4/v0.5/v0.7 message
//!                              (0x0E = ListRules, 0x11 = DeleteInstallArtifacts, v0.7;
//!                               0x07/0x0F/0x10 formerly TrustPolicy/ListTrust/IsTrusted — removed)
//!                              (0x12 = DenyNotify, v0.3)
//!                              (0x13 = ExecBlocked, v0.4 M003-S02)
//!                              (0x14 = PersistenceWrite, v0.4 M003-S04)
//!                              (0x15 = Ping, v0.5 M004-S01)
//!                              (0x16 = DisableCuratedRule, v1.0)
//!                              (0x17 = EnableCuratedRule, v1.0)
//!   - 0x00                   → legacy RegisterRoot (v0.1)
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
    // 0x07 was TrustPolicy (removed)
    EnvNotPropagatedGap = 0x08,
    // v0.3 — new IPC tag bytes:
    Status = 0x09,
    PromptChannelInit = 0x0A,
    InsertUserRule = 0x0B,
    ReadInstallArtifacts = 0x0C,
    BaselineCommit = 0x0D,
    // v0.7 — management-IPC family (additive at IPC_SCHEMA_V3):
    ListRules = 0x0E,
    // 0x0F was ListTrust (removed)
    // 0x10 was IsTrusted (removed)
    DeleteInstallArtifacts = 0x11,
    // v0.3 — deny-notify IPC:
    DenyNotify = 0x12,
    // v0.4 — M003-S02 hardened-runtime exec blocking:
    ExecBlocked = 0x13,
    // v0.4 — M003-S04 persistence-path monitoring:
    PersistenceWrite = 0x14,
    // v0.5 — M004-S01 watchdog liveness:
    Ping = 0x15,
    // v1.0 — curated rule overrides:
    DisableCuratedRule = 0x16,
    EnableCuratedRule = 0x17,
}

impl MessageTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x02 => Some(Self::PrepareSnapshot),
            0x03 => Some(Self::ForkEvent),
            0x04 => Some(Self::ExecEvent),
            0x05 => Some(Self::DylibLoaded),
            0x06 => Some(Self::Resolve),
            // 0x07 was TrustPolicy (removed)
            0x08 => Some(Self::EnvNotPropagatedGap),
            // v0.3:
            0x09 => Some(Self::Status),
            0x0A => Some(Self::PromptChannelInit),
            0x0B => Some(Self::InsertUserRule),
            0x0C => Some(Self::ReadInstallArtifacts),
            0x0D => Some(Self::BaselineCommit),
            // v0.7:
            0x0E => Some(Self::ListRules),
            // 0x0F was ListTrust (removed)
            // 0x10 was IsTrusted (removed)
            0x11 => Some(Self::DeleteInstallArtifacts),
            // v0.3 — deny-notify:
            0x12 => Some(Self::DenyNotify),
            0x13 => Some(Self::ExecBlocked),
            0x14 => Some(Self::PersistenceWrite),
            0x15 => Some(Self::Ping),
            // v1.0:
            0x16 => Some(Self::DisableCuratedRule),
            0x17 => Some(Self::EnableCuratedRule),
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
    /// v0.1 legacy: caller should treat the already-peeked byte as the
    /// FIRST byte of a 4-byte length prefix (always 0x00 in valid legacy
    /// frames per MAX_FRAME_BYTES = 64 KiB) and read the rest of the frame
    /// as length-prefixed CBOR (RegisterRoot).
    LegacyUntagged { first_length_byte: u8 },
    /// v0.2+: caller should read a length-prefixed CBOR body of this type.
    Tagged(MessageTag),
}

/// Peek the first byte to decide framing kind. Reads exactly 1 byte from the
/// stream — caller must continue with the appropriate read path.
///
/// WARNING: only 0x00 (legacy length-prefix high byte) and 0x02..=0x17
/// (v0.2..v0.7 tags) are valid first bytes. Anything else is a protocol
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
        // v0.1 legacy length-prefixed frame's high byte (always 0x00 for
        // any frame ≤ MAX_FRAME_BYTES = 64 KiB).
        return Ok(FrameKind::LegacyUntagged {
            first_length_byte: b,
        });
    }
    // Anything else: not a valid v0.2+ tag and not a valid legacy
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
            MessageTag::EnvNotPropagatedGap,
            // v0.3:
            MessageTag::Status,
            MessageTag::PromptChannelInit,
            MessageTag::InsertUserRule,
            MessageTag::ReadInstallArtifacts,
            MessageTag::BaselineCommit,
            // v0.7:
            MessageTag::ListRules,
            MessageTag::DeleteInstallArtifacts,
            // v0.3:
            MessageTag::DenyNotify,
            // v0.4 M003-S02:
            MessageTag::ExecBlocked,
            // v0.4 M003-S04:
            MessageTag::PersistenceWrite,
            // v0.5 M004-S01:
            MessageTag::Ping,
            // v1.0:
            MessageTag::DisableCuratedRule,
            MessageTag::EnableCuratedRule,
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
        // 0x07 was TrustPolicy, 0x0F was ListTrust, 0x10 was IsTrusted (all removed).
        assert!(MessageTag::from_byte(0x07).is_none());
        assert!(MessageTag::from_byte(0x0F).is_none());
        assert!(MessageTag::from_byte(0x10).is_none());
        // 0x18+ — unassigned tag space (0x17 = EnableCuratedRule, v1.0).
        assert!(MessageTag::from_byte(0x18).is_none());
        assert!(MessageTag::from_byte(0xff).is_none());
    }

    #[test]
    fn tag_byte_values_are_stable() {
        // Wire-stable values — never renumber once shipped.
        // v0.2:
        assert_eq!(MessageTag::PrepareSnapshot.as_byte(), 0x02);
        assert_eq!(MessageTag::ForkEvent.as_byte(), 0x03);
        assert_eq!(MessageTag::ExecEvent.as_byte(), 0x04);
        assert_eq!(MessageTag::DylibLoaded.as_byte(), 0x05);
        assert_eq!(MessageTag::Resolve.as_byte(), 0x06);
        // 0x07 was TrustPolicy (removed)
        assert_eq!(MessageTag::from_byte(0x07), None);
        assert_eq!(MessageTag::EnvNotPropagatedGap.as_byte(), 0x08);
        // v0.3:
        assert_eq!(MessageTag::Status.as_byte(), 0x09);
        assert_eq!(MessageTag::PromptChannelInit.as_byte(), 0x0A);
        assert_eq!(MessageTag::InsertUserRule.as_byte(), 0x0B);
        assert_eq!(MessageTag::ReadInstallArtifacts.as_byte(), 0x0C);
        assert_eq!(MessageTag::BaselineCommit.as_byte(), 0x0D);
        // v0.7:
        assert_eq!(MessageTag::ListRules as u8, 0x0E);
        // 0x0F was ListTrust (removed)
        assert_eq!(MessageTag::from_byte(0x0F), None);
        // 0x10 was IsTrusted (removed)
        assert_eq!(MessageTag::from_byte(0x10), None);
        assert_eq!(MessageTag::DeleteInstallArtifacts as u8, 0x11);
        // from_byte round-trips for all v0.3 tags:
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
        // v0.7:
        assert_eq!(MessageTag::from_byte(0x0E), Some(MessageTag::ListRules));
        assert_eq!(
            MessageTag::from_byte(0x11),
            Some(MessageTag::DeleteInstallArtifacts)
        );
        // v0.3:
        assert_eq!(MessageTag::DenyNotify as u8, 0x12);
        assert_eq!(MessageTag::from_byte(0x12), Some(MessageTag::DenyNotify));
        // v0.4 M003-S02:
        assert_eq!(MessageTag::ExecBlocked as u8, 0x13);
        assert_eq!(MessageTag::from_byte(0x13), Some(MessageTag::ExecBlocked));
        // v0.4 M003-S04:
        assert_eq!(MessageTag::PersistenceWrite as u8, 0x14);
        assert_eq!(MessageTag::from_byte(0x14), Some(MessageTag::PersistenceWrite));
        // v0.5 M004-S01:
        assert_eq!(MessageTag::Ping as u8, 0x15);
        assert_eq!(MessageTag::from_byte(0x15), Some(MessageTag::Ping));
        // v1.0:
        assert_eq!(MessageTag::DisableCuratedRule as u8, 0x16);
        assert_eq!(MessageTag::from_byte(0x16), Some(MessageTag::DisableCuratedRule));
        assert_eq!(MessageTag::EnableCuratedRule as u8, 0x17);
        assert_eq!(MessageTag::from_byte(0x17), Some(MessageTag::EnableCuratedRule));
        // 0x18 is unassigned — must return None:
        assert_eq!(MessageTag::from_byte(0x18), None);
    }
}
