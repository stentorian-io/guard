#[cfg(target_os = "macos")]
use guard_core::identity::audit_token_to_pid;
use guard_core::identity::{AuditToken, ProcessIdentity};

#[test]
fn unverified_returns_none_as_policy_key() {
    let id = ProcessIdentity::from_pid_unverified(42);
    assert!(
        id.as_policy_key().is_none(),
        "Unverified must not serve as policy key (ENF-08)"
    );
}

#[test]
fn verified_returns_some_as_policy_key() {
    let tok = AuditToken::synthetic([0, 0, 0, 0, 0, 4242, 0, 7]);
    let id = unsafe { ProcessIdentity::from_kernel_token(tok) };
    let k = id
        .as_policy_key()
        .expect("Verified must yield a policy key");
    assert_eq!(k.val, tok.val);
    assert_eq!(k.pid(), 4242);
    assert_eq!(k.pidversion(), 7);
}

#[test]
fn pid_accessor_works_for_both_variants() {
    let v_id = unsafe {
        ProcessIdentity::from_kernel_token(AuditToken::synthetic([0, 0, 0, 0, 0, 9001, 0, 0]))
    };
    let u_id = ProcessIdentity::from_pid_unverified(42);
    assert_eq!(v_id.pid(), 9001);
    assert_eq!(u_id.pid(), 42);
}

/// A8: validate that audit_token_to_pid agrees with our val[5] interpretation.
/// This calls into Apple's libbsm and returns whatever the kernel says.
#[cfg(target_os = "macos")]
#[test]
fn audit_token_to_pid_agrees_with_val_5() {
    let t = AuditToken::synthetic([1, 2, 3, 4, 5, 6789, 7, 8]);
    let p = unsafe { audit_token_to_pid(&t) };
    assert_eq!(
        p, 6789,
        "audit_token_to_pid must read val[5] (knight.sc layout)"
    );
}
