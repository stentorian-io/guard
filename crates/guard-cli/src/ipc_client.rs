//! Connect to the daemon socket, send messages, await Replies.
//!
//! ISS-08 remediation: bounded read/write timeouts around Unix-domain IPC.
//! `AF_UNIX` connect failures are local and immediate on Darwin for the daemon
//! states we care about (missing socket, refused dead socket, permission
//! denied). `socket2::connect_timeout` is not reliable for this macOS Unix
//! socket path, so connect uses `UnixStream::connect` directly.

use crate::CliError;
use guard_core::AuditToken;
use guard_ipc::frame::{read_frame, read_frame_with_limit, write_frame, write_frame_with_limit};
use guard_ipc::{
    BaselineCommit, BaselineCommitReply, DeleteInstallArtifacts, DeleteInstallArtifactsReply,
    DisableCuratedRule, DisableCuratedRuleReply, EnableCuratedRule, EnableCuratedRuleReply,
    InsertUserRule, InsertUserRuleReply, InstallArtifact, ListRules, ListRulesReply,
    PrepareSnapshot, ProposedRule, PublishSignedSnapshot, ReadInstallArtifacts,
    ReadInstallArtifactsReply, RegisterRoot, Reply, RuleRow, SnapshotInputsReply, SnapshotReply,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Tag bytes — must match the v0.2 MessageTag values exactly. The dylib
// uses the same values in `guard_hook::ipc_client`.
const TAG_STATUS: u8 = 0x09;
pub(crate) const TAG_PROMPT_CHANNEL_INIT: u8 = 0x0A;
const TAG_INSERT_USER_RULE: u8 = 0x0B;
const TAG_READ_INSTALL_ARTIFACTS: u8 = 0x0C;
const TAG_LIST_RULES: u8 = 0x0E;
const TAG_BASELINE_COMMIT: u8 = 0x0D;
const TAG_DELETE_INSTALL_ARTIFACTS: u8 = 0x11;
const TAG_DISABLE_CURATED_RULE: u8 = 0x16;
const TAG_ENABLE_CURATED_RULE: u8 = 0x17;
const TAG_PREPARE_SNAPSHOT_INPUTS: u8 = 0x18;
const TAG_PUBLISH_SIGNED_SNAPSHOT: u8 = 0x19;

fn max_frame_bytes_for_tag(tag: u8) -> u32 {
    match tag {
        TAG_PREPARE_SNAPSHOT_INPUTS | TAG_PUBLISH_SIGNED_SNAPSHOT => {
            guard_ipc::frame::MAX_SNAPSHOT_FRAME_BYTES
        }
        _ => guard_ipc::frame::MAX_FRAME_BYTES,
    }
}

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// `PrepareSnapshot`'s read timeout is generous to accommodate snapshot
/// generation on large rule sets.
const PREPARE_SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to the daemon socket and configure bounded read/write timeouts.
///
/// # Errors
///
/// Returns an error when the daemon socket cannot be opened.
pub(crate) fn connect_with_timeout(sock: &Path) -> Result<UnixStream, CliError> {
    let stream = UnixStream::connect(sock)
        .map_err(|e| CliError::DaemonUnreachable(format!("connect({}): {e}", sock.display())))?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
    stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
    Ok(stream)
}

/// ISS-08 remediation: connect-only liveness probe sent BEFORE spawning the
/// wrapped child. If the daemon is unreachable, the CLI exits 70 (`EX_SOFTWARE`)
/// without having forked an unprotected child — keeping T-01-08-06's promise.
///
/// Why connect-only (no frame sent):
///   - The socket file at `sock` is bound by the daemon (`UnixListener::bind`).
///     A non-running daemon yields ECONNREFUSED or ENOENT, so a successful
///     `connect_timeout` IS sufficient liveness evidence.
///   - Sending a frame would require defining a new wire message type
///     (avoided: keeps the IPC schema minimal and forward-compatible).
///   - The daemon's `ipc_server::handle` tolerates the resulting EOF on
///     `read_frame` as a benign liveness probe (no state change, no panic,
///     idle log line at debug level).
///
/// The stream is dropped immediately on success; the daemon's `accept()` sees
/// a connect+immediate-close, which is the documented benign liveness path.
///
/// # Errors
///
/// Returns an error when the daemon socket cannot be reached.
pub fn probe_daemon_alive(sock: &Path) -> Result<(), CliError> {
    let _stream = connect_with_timeout(sock)?;
    // Stream dropped here; the daemon will see EOF on its first read_frame
    // and treat it as a benign liveness check.
    Ok(())
}

/// Register the current root process with the daemon.
///
/// # Errors
///
/// Returns an error when IPC fails or the daemon rejects the registration.
pub fn register_root_with_daemon(sock: &Path, token: AuditToken) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new(token);
    send_register_root(&mut stream, &msg)
}

/// Register the current root process and run UUID with the daemon.
///
/// # Errors
///
/// Returns an error when IPC fails or the daemon rejects the registration.
pub fn register_root_for_run_with_daemon(
    sock: &Path,
    token: AuditToken,
    run_uuid: &str,
) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new_for_run(token, run_uuid);
    send_register_root(&mut stream, &msg)
}

/// Register the current root process, run UUID, and captured package-manager
/// environment with the daemon.
///
/// # Errors
///
/// Returns an error when IPC fails or the daemon rejects the registration.
pub fn register_root_for_run_with_pm_env_with_daemon(
    sock: &Path,
    token: AuditToken,
    run_uuid: &str,
    pm_env: Vec<(String, String)>,
) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new_for_run_with_pm_env(token, run_uuid, pm_env);
    send_register_root(&mut stream, &msg)
}

fn send_register_root(
    stream: &mut std::os::unix::net::UnixStream,
    msg: &RegisterRoot,
) -> Result<(), CliError> {
    write_frame(stream, msg)?;
    let reply: Reply = read_frame(stream)?;
    match reply {
        Reply::Ack { .. } => Ok(()),
        Reply::Err { message, .. } => {
            Err(CliError::DaemonUnreachable(format!("daemon: {message}")))
        }
    }
}

/// Send a v0.2 tagged frame: `[1-byte tag][4-byte BE length][CBOR body]`,
/// then read the daemon's tag-echoed reply: `[1-byte tag][4-byte BE length][CBOR body]`.
///
/// Wire shape symmetry with:
///   - daemon-side:  `crates/guard-daemon/src/ipc_server.rs::write_tagged`
///   - dylib-side:   `crates/guard-hook/src/ipc_client.rs::send_tagged_and_recv_ack`
fn send_tagged_request<Req, ReplyT>(sock: &Path, tag: u8, req: &Req) -> Result<ReplyT, CliError>
where
    Req: serde::Serialize,
    ReplyT: serde::de::DeserializeOwned,
{
    send_tagged_request_with_read_timeout(sock, tag, req, READ_TIMEOUT)
}

/// WR-11 fix: variant of `send_tagged_request` that overrides the read
/// timeout for the reply. Used by `prepare_snapshot_v3` so the CLI
/// doesn't trip its default 5s read timeout while the daemon is in the
/// middle of a 60s/120s `fetch_feeds_blocking` call (which would
/// surface "`DaemonUnreachable`" instead of a genuine fetch error).
fn send_tagged_request_with_read_timeout<Req, ReplyT>(
    sock: &Path,
    tag: u8,
    req: &Req,
    read_timeout: Duration,
) -> Result<ReplyT, CliError>
where
    Req: serde::Serialize,
    ReplyT: serde::de::DeserializeOwned,
{
    let mut stream = connect_with_timeout(sock)?;
    if read_timeout != READ_TIMEOUT {
        let _ = stream.set_read_timeout(Some(read_timeout));
    }
    stream
        .write_all(&[tag])
        .map_err(|e| CliError::DaemonUnreachable(format!("tag write: {e}")))?;

    write_frame_with_limit(&mut stream, req, max_frame_bytes_for_tag(tag))
        .map_err(|e| CliError::DaemonUnreachable(format!("write frame: {e}")))?;
    let mut tag_back = [0u8; 1];
    stream
        .read_exact(&mut tag_back)
        .map_err(|e| CliError::DaemonUnreachable(format!("read tag echo: {e}")))?;
    if tag_back[0] != tag {
        return Err(CliError::DaemonUnreachable(format!(
            "tag mismatch: sent 0x{tag:02x}, got 0x{:02x}",
            tag_back[0]
        )));
    }
    let reply: ReplyT = read_frame_with_limit(&mut stream, max_frame_bytes_for_tag(tag))
        .map_err(|e| CliError::DaemonUnreachable(format!("read reply: {e}")))?;
    Ok(reply)
}

/// Send `PrepareSnapshot { cwd }` BEFORE `posix_spawn` so the daemon merges
/// curated YAML + `SQLite` rules, writes a per-run snapshot to
/// `${state_dir}/runs/{uuid}.cbor`, and returns the manifest path. The CLI
/// then sets that manifest path as `STT_GUARD_SNAPSHOT_MANIFEST` in the
/// wrapped child's envp so the dylib loads the per-run policy.
///
/// # Errors
///
/// Returns an error when snapshot input retrieval, local snapshot building,
/// signing, or daemon publication fails.
pub fn prepare_snapshot(sock: &Path, cwd: &Path) -> Result<(PathBuf, String), CliError> {
    let outcome = prepare_snapshot_v3(sock, cwd, false, false)?;
    Ok((outcome.manifest_path, outcome.run_uuid))
}

#[derive(Debug, Clone)]
pub struct PrepareSnapshotOutcome {
    pub manifest_path: PathBuf,
    pub run_uuid: String,
}

/// V3 `PrepareSnapshot` with `is_tty` + `learn_mode`.
///
/// # Errors
///
/// Returns an error when snapshot input retrieval, local snapshot building,
/// signing, or daemon publication fails.
pub fn prepare_snapshot_v3(
    sock: &Path,
    cwd: &Path,
    is_tty: bool,
    learn_mode: bool,
) -> Result<PrepareSnapshotOutcome, CliError> {
    let req = PrepareSnapshot::new_v3(cwd.display().to_string(), is_tty, learn_mode);
    let inputs_reply: SnapshotInputsReply = send_tagged_request_with_read_timeout(
        sock,
        TAG_PREPARE_SNAPSHOT_INPUTS,
        &req,
        PREPARE_SNAPSHOT_READ_TIMEOUT,
    )?;
    let (input, is_tty, baseline_mode) = match inputs_reply {
        SnapshotInputsReply::Ok {
            input,
            is_tty,
            baseline_mode,
            ..
        } => (input, is_tty, baseline_mode),
        SnapshotInputsReply::Err { message, .. } => {
            return Err(CliError::Other(format!("PrepareSnapshotInputs: {message}")));
        }
    };
    let run_uuid = input.run_uuid.clone();
    let generated_at_unix_ms = input.generated_at_unix_ms;
    let snapshot_bytes = guard_core::build_snapshot_bytes(input)
        .map_err(|e| CliError::Other(format!("build snapshot: {e}")))?;
    let snapshot_sha256 = guard_core::sha256_hex(&snapshot_bytes);
    let payload = guard_core::SnapshotSignaturePayloadV1::new(
        run_uuid.clone(),
        snapshot_sha256,
        generated_at_unix_ms,
    );
    let signature = crate::rule_signing::sign_snapshot_payload(&payload)?;
    let publish = PublishSignedSnapshot::new(
        run_uuid.clone(),
        snapshot_bytes,
        signature,
        is_tty,
        baseline_mode,
    );
    let reply: SnapshotReply = send_tagged_request_with_read_timeout(
        sock,
        TAG_PUBLISH_SIGNED_SNAPSHOT,
        &publish,
        PREPARE_SNAPSHOT_READ_TIMEOUT,
    )?;
    match reply {
        SnapshotReply::Ok {
            manifest_path,
            run_uuid,
            ..
        } => Ok(PrepareSnapshotOutcome {
            manifest_path: PathBuf::from(manifest_path),
            run_uuid,
        }),
        SnapshotReply::Err { message, .. } => {
            Err(CliError::Other(format!("PublishSignedSnapshot: {message}")))
        }
    }
}

/// v0.3 tag 0x09: request daemon status.
///
/// # Errors
///
/// Returns an error when daemon IPC fails or the status reply cannot be decoded.
pub fn status_request(sock: &Path) -> Result<guard_ipc::StatusReply, CliError> {
    let req = guard_ipc::Status::new();
    send_tagged_request(sock, TAG_STATUS, &req)
}

/// v0.3 tag 0x0B: insert a user rule into the daemon's rule store.
/// Requires biometric authentication (Touch ID / password) before sending.
///
/// # Errors
///
/// Returns an error when authentication, signing, IPC, or daemon insertion
/// fails.
pub fn insert_user_rule_request(
    sock: &Path,
    kind: &str,
    match_type: &str,
    pattern: &str,
    reason: &str,
) -> Result<i64, CliError> {
    insert_user_rule_request_with_origin(sock, kind, match_type, pattern, reason, "manual", None)
}

/// Insert a user rule with explicit origin metadata.
///
/// # Errors
///
/// Returns an error when authentication, signing, IPC, or daemon insertion
/// fails.
pub fn insert_user_rule_request_with_origin(
    sock: &Path,
    kind: &str,
    match_type: &str,
    pattern: &str,
    reason: &str,
    origin: &str,
    run_uuid: Option<&str>,
) -> Result<i64, CliError> {
    let bio_reason = format!("create {kind} rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let created_at_unix_ms = unix_ms_now();
    let payload = guard_core::RuleSignaturePayloadV1::new(
        kind,
        match_type,
        pattern,
        reason,
        created_at_unix_ms,
        origin,
        run_uuid.map(str::to_string),
    );
    let signature = crate::rule_signing::sign_rule_payload(&payload)?;
    let req = InsertUserRule {
        schema_version: guard_ipc::IPC_SCHEMA_V5,
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: pattern.into(),
        reason: reason.into(),
        created_at_unix_ms,
        origin: origin.into(),
        run_uuid: run_uuid.map(str::to_string),
        signature: Some(signature),
    };
    let reply: InsertUserRuleReply = send_tagged_request(sock, TAG_INSERT_USER_RULE, &req)?;
    match reply {
        InsertUserRuleReply::Ok { rule_id, .. } => Ok(rule_id),
        InsertUserRuleReply::Err { message, .. } => {
            Err(CliError::Other(format!("InsertUserRule: {message}")))
        }
    }
}

/// v0.3 tag 0x0C: read install artifacts from the daemon.
///
/// # Errors
///
/// Returns an error when daemon IPC fails or the daemon returns an error reply.
pub fn read_install_artifacts_request(sock: &Path) -> Result<Vec<InstallArtifact>, CliError> {
    let req = ReadInstallArtifacts::new();
    let reply: ReadInstallArtifactsReply =
        send_tagged_request(sock, TAG_READ_INSTALL_ARTIFACTS, &req)?;
    match reply {
        ReadInstallArtifactsReply::Ok { artifacts, .. } => Ok(artifacts),
        ReadInstallArtifactsReply::Err { message, .. } => {
            Err(CliError::Other(format!("ReadInstallArtifacts: {message}")))
        }
    }
}

/// Clear `install_artifacts` rows for the given
/// kinds. Invoked by `uninstall::components::remove_*` helpers after their
/// on-disk teardown so the daemon's view of installed artifacts matches
/// reality. Errors are surfaced as `CliError::Other`; callers typically
/// ignore them (best-effort cleanup — the daemon may be shutting down
/// concurrently with the global-remove path).
///
/// Returns the row count removed by the daemon (sum of per-kind delete
/// results).
///
/// # Errors
///
/// Returns an error when daemon IPC fails or the daemon returns an error reply.
pub fn delete_install_artifacts_request(sock: &Path, kinds: Vec<String>) -> Result<u64, CliError> {
    let req = DeleteInstallArtifacts::new(kinds);
    let reply: DeleteInstallArtifactsReply =
        send_tagged_request(sock, TAG_DELETE_INSTALL_ARTIFACTS, &req)?;
    match reply {
        DeleteInstallArtifactsReply::Ok { removed, .. } => Ok(removed),
        DeleteInstallArtifactsReply::Err { message, .. } => Err(CliError::Other(format!(
            "DeleteInstallArtifacts: {message}"
        ))),
    }
}

/// List user rules (and optionally builtins) from the daemon.
///
/// # Errors
///
/// Returns an error when daemon IPC fails or the daemon returns an error reply.
pub fn list_rules_request(sock: &Path, include_builtins: bool) -> Result<Vec<RuleRow>, CliError> {
    let req = ListRules::new(include_builtins);
    let reply: ListRulesReply = send_tagged_request(sock, TAG_LIST_RULES, &req)?;
    match reply {
        ListRulesReply::Ok { rules, .. } => Ok(rules),
        ListRulesReply::Err { message, .. } => {
            Err(CliError::Other(format!("ListRules: {message}")))
        }
    }
}

/// Disable a curated (built-in) rule by pattern.
/// Requires biometric authentication (Touch ID / password).
///
/// # Errors
///
/// Returns an error when authentication, signing, IPC, or daemon update fails.
pub fn disable_curated_rule_request(
    sock: &Path,
    pattern: &str,
    reason: &str,
) -> Result<(), CliError> {
    let bio_reason = format!("disable curated rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let created_at_unix_ms = unix_ms_now();
    let payload = guard_core::ManagementActionPayloadV1::new(
        guard_daemon::management_auth::ACTION_DISABLE_CURATED_RULE,
        pattern,
        reason,
        created_at_unix_ms,
    );
    let signature = crate::rule_signing::sign_management_action_payload(&payload)?;
    let req = DisableCuratedRule::new_signed(pattern, reason, created_at_unix_ms, signature);
    let reply: DisableCuratedRuleReply = send_tagged_request(sock, TAG_DISABLE_CURATED_RULE, &req)?;
    match reply {
        DisableCuratedRuleReply::Ok { .. } => Ok(()),
        DisableCuratedRuleReply::Err { message, .. } => {
            Err(CliError::Other(format!("DisableCuratedRule: {message}")))
        }
    }
}

/// Re-enable a previously disabled curated rule by pattern.
/// Requires biometric authentication (Touch ID / password).
///
/// # Errors
///
/// Returns an error when authentication, signing, IPC, or daemon update fails.
pub fn enable_curated_rule_request(sock: &Path, pattern: &str) -> Result<bool, CliError> {
    let bio_reason = format!("re-enable curated rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let created_at_unix_ms = unix_ms_now();
    let payload = guard_core::ManagementActionPayloadV1::new(
        guard_daemon::management_auth::ACTION_ENABLE_CURATED_RULE,
        pattern,
        "",
        created_at_unix_ms,
    );
    let signature = crate::rule_signing::sign_management_action_payload(&payload)?;
    let req = EnableCuratedRule::new_signed(pattern, created_at_unix_ms, signature);
    let reply: EnableCuratedRuleReply = send_tagged_request(sock, TAG_ENABLE_CURATED_RULE, &req)?;
    match reply {
        EnableCuratedRuleReply::Ok { was_disabled, .. } => Ok(was_disabled),
        EnableCuratedRuleReply::Err { message, .. } => {
            Err(CliError::Other(format!("EnableCuratedRule: {message}")))
        }
    }
}

/// Commit baseline staging for a learn-mode run. Returns the proposed rules
/// accumulated during the run.
///
/// # Errors
///
/// Returns an error when daemon IPC fails or the daemon rejects the commit.
pub fn baseline_commit_request(sock: &Path, run_uuid: &str) -> Result<Vec<ProposedRule>, CliError> {
    let req = BaselineCommit {
        schema_version: guard_ipc::IPC_SCHEMA_V3,
        run_uuid: run_uuid.to_string(),
    };
    let reply: BaselineCommitReply = send_tagged_request(sock, TAG_BASELINE_COMMIT, &req)?;
    match reply {
        BaselineCommitReply::Ok { proposed_rules, .. } => Ok(proposed_rules),
        BaselineCommitReply::Err { message, .. } => {
            Err(CliError::Other(format!("BaselineCommit: {message}")))
        }
    }
}

fn unix_ms_now() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}
