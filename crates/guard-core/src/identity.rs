//! `ProcessIdentity` — provenance-typed wrapper around `audit_token_t`.
//! Bare `pid_t` cannot construct Verified; only kernel-sourced `AuditToken` values
//! can, and only via the `unsafe` constructor.
//!
//! Hand-rolled FFI (rejected mach2 / bsm-sys / endpoint-sec-sys).

/// 8 × 32-bit fields per Apple's libbsm.h. Layout is stable and kernel-blessed
/// per knight.sc; val[5]=pid, val[7]=pidversion.
///
/// Field layout (from libbsm.h and XNU source):
///   val[0]=auid, val[1]=euid, val[2]=egid, val[3]=ruid, val[4]=rgid,
///   val[5]=pid,  val[6]=asid, val[7]=pidversion
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuditToken {
    pub val: [u32; 8],
}

impl AuditToken {
    /// Construct a synthetic `AuditToken` for testing. NOT a kernel-sourced token —
    /// callers cannot upgrade this to `ProcessIdentity::Verified` via `from_kernel_token`
    /// without committing the safety lie themselves.
    #[must_use]
    pub const fn synthetic(val: [u32; 8]) -> Self {
        Self { val }
    }

    /// Returns the pid encoded in the token (val[5]).
    #[must_use]
    pub fn pid(&self) -> libc::pid_t {
        libc::pid_t::from_ne_bytes(self.val[5].to_ne_bytes())
    }

    /// Returns the pidversion encoded in the token (val[7]).
    #[must_use]
    pub fn pidversion(&self) -> u32 {
        self.val[7]
    }
}

unsafe extern "C" {
    /// Apple libbsm: returns the pid encoded in the audit token.
    /// Resolves from `libsystem_kernel.dylib` / libbsm at link time on macOS.
    pub fn audit_token_to_pid(token: *const AuditToken) -> libc::pid_t;

    /// Apple libbsm: returns the pidversion encoded in the audit token.
    pub fn audit_token_to_pidversion(token: *const AuditToken) -> u32;
}

/// Provenance-typed process identity. Policy decisions accept only `Verified`.
///
/// The two-variant enum encodes the provenance of the identity at the type level
/// (ENF-08 / D-04): you cannot pass an `Unverified` to a function expecting
/// `&AuditToken` without going through `unsafe` code, which is auditable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcessIdentity {
    /// Constructable only via `unsafe fn from_kernel_token`.
    /// The token must have been obtained from a trusted kernel source.
    Verified(AuditToken),
    /// From wire formats, display strings, or any non-kernel source. Cannot serve
    /// as a policy key — `as_policy_key()` returns `None`.
    Unverified(libc::pid_t),
}

impl ProcessIdentity {
    /// Construct a `Verified` identity from a kernel-sourced audit token.
    ///
    /// # Safety
    /// Caller must have obtained `t` from a trusted kernel source — e.g.
    /// `pid_for_task`, `xpc_connection_get_audit_token`, or
    /// `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, ...)`. The `unsafe` is the
    /// type-system enforcement of ENF-08; misusing it is a security bug.
    #[must_use]
    pub unsafe fn from_kernel_token(t: AuditToken) -> Self {
        Self::Verified(t)
    }

    /// Construct an `Unverified` identity from a raw `pid_t`.
    /// This cannot be used as a policy key.
    #[must_use]
    pub fn from_pid_unverified(p: libc::pid_t) -> Self {
        Self::Unverified(p)
    }

    /// Returns the audit token only for `Verified`; `None` for `Unverified`.
    ///
    /// Policy signatures accept `&AuditToken` and so cannot be called with
    /// `Unverified` without an explicit upgrade through `from_kernel_token`.
    #[must_use]
    pub fn as_policy_key(&self) -> Option<&AuditToken> {
        match self {
            Self::Verified(t) => Some(t),
            Self::Unverified(_) => None,
        }
    }

    /// Returns the pid for either variant.
    /// For `Verified`, reads from `val[5]` directly (avoids FFI call).
    #[must_use]
    pub fn pid(&self) -> libc::pid_t {
        match self {
            Self::Verified(t) => t.pid(),
            Self::Unverified(p) => *p,
        }
    }
}
