//! Connect to the daemon socket, send messages, await Replies.
//!
//! ISS-08 remediation: bounded read/write timeouts around Unix-domain IPC.
//! AF_UNIX connect failures are local and immediate on Darwin for the daemon
//! states we care about (missing socket, refused dead socket, permission
//! denied). `socket2::connect_timeout` is not reliable for this macOS Unix
//! socket path, so connect uses `UnixStream::connect` directly.

use crate::CliError;
use guard_core::AuditToken;
use guard_ipc::frame::{read_frame, write_frame};
use guard_ipc::{
    BaselineCommit, BaselineCommitReply, DeleteInstallArtifacts, DeleteInstallArtifactsReply,
    DisableCuratedRule, DisableCuratedRuleReply, EnableCuratedRule, EnableCuratedRuleReply,
    InsertUserRule, InsertUserRuleReply, InstallArtifact, ListRules, ListRulesReply,
    PrepareSnapshot, ProposedRule, ReadInstallArtifacts, ReadInstallArtifactsReply, RegisterRoot,
    Reply, RuleRow, SnapshotReply,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Tag bytes — must match the v0.2 MessageTag values exactly. The dylib
// uses the same values in `guard_hook::ipc_client`.
const TAG_PREPARE_SNAPSHOT: u8 = 0x02;
const TAG_STATUS: u8 = 0x09;
pub(crate) const TAG_PROMPT_CHANNEL_INIT: u8 = 0x0A;
const TAG_INSERT_USER_RULE: u8 = 0x0B;
const TAG_READ_INSTALL_ARTIFACTS: u8 = 0x0C;
const TAG_LIST_RULES: u8 = 0x0E;
const TAG_BASELINE_COMMIT: u8 = 0x0D;
const TAG_DELETE_INSTALL_ARTIFACTS: u8 = 0x11;
const TAG_DISABLE_CURATED_RULE: u8 = 0x16;
const TAG_ENABLE_CURATED_RULE: u8 = 0x17;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn load_ipc_hmac_key(sock: &Path) -> Option<[u8; 32]> {
    let state_dir = sock.parent()?;
    guard_daemon::hmac_key::load(state_dir)
}

/// PrepareSnapshot's read timeout is generous to accommodate snapshot
/// generation on large rule sets.
const PREPARE_SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to the daemon socket and configure bounded read/write timeouts.
pub(crate) fn connect_with_timeout(sock: &Path) -> Result<UnixStream, CliError> {
    let stream = UnixStream::connect(sock)
        .map_err(|e| CliError::DaemonUnreachable(format!("connect({}): {e}", sock.display())))?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
    stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
    Ok(stream)
}

/// ISS-08 remediation: connect-only liveness probe sent BEFORE spawning the
/// wrapped child. If the daemon is unreachable, the CLI exits 70 (EX_SOFTWARE)
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
pub fn probe_daemon_alive(sock: &Path) -> Result<(), CliError> {
    let _stream = connect_with_timeout(sock)?;
    // Stream dropped here; the daemon will see EOF on its first read_frame
    // and treat it as a benign liveness check.
    Ok(())
}

pub fn register_root_with_daemon(sock: &Path, token: AuditToken) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new(token);
    send_register_root(&mut stream, msg)
}

pub fn register_root_for_run_with_daemon(
    sock: &Path,
    token: AuditToken,
    run_uuid: &str,
) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new_for_run(token, run_uuid);
    send_register_root(&mut stream, msg)
}

pub fn register_root_for_run_with_pm_env_with_daemon(
    sock: &Path,
    token: AuditToken,
    run_uuid: &str,
    pm_env: Vec<(String, String)>,
) -> Result<(), CliError> {
    let mut stream = connect_with_timeout(sock)?;
    let msg = RegisterRoot::new_for_run_with_pm_env(token, run_uuid, pm_env);
    send_register_root(&mut stream, msg)
}

fn send_register_root(
    stream: &mut std::os::unix::net::UnixStream,
    msg: RegisterRoot,
) -> Result<(), CliError> {
    write_frame(stream, &msg)?;
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
/// surface "DaemonUnreachable" instead of a genuine fetch error).
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

    if let Some(key) = load_ipc_hmac_key(sock) {
        let mut signer = guard_ipc::signed_frame::FrameSigner::new(key);
        signer
            .write_signed(&mut stream, tag, req)
            .map_err(|e| CliError::DaemonUnreachable(format!("write signed: {e}")))?;
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
        let reply: ReplyT = signer
            .read_signed(&mut stream, tag)
            .map_err(|e| CliError::DaemonUnreachable(format!("read signed reply: {e}")))?;
        Ok(reply)
    } else {
        write_frame(&mut stream, req)
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
        let reply: ReplyT = read_frame(&mut stream)
            .map_err(|e| CliError::DaemonUnreachable(format!("read reply: {e}")))?;
        Ok(reply)
    }
}

/// Send `PrepareSnapshot { cwd }` BEFORE posix_spawn so the daemon merges
/// curated YAML + SQLite rules, writes a per-run snapshot to
/// `${state_dir}/runs/{uuid}.cbor`, and returns the manifest path. The CLI
/// then sets that manifest path as `STT_GUARD_SNAPSHOT_MANIFEST` in the
/// wrapped child's envp so the dylib loads the per-run policy.
pub fn prepare_snapshot(sock: &Path, cwd: &Path) -> Result<(PathBuf, String), CliError> {
    let req = PrepareSnapshot::new(cwd.display().to_string());
    // WR-11: use the extended read timeout so the CLI doesn't trip a
    // false "DaemonUnreachable" while the daemon is mid-fetch.
    let reply: SnapshotReply = send_tagged_request_with_read_timeout(
        sock,
        TAG_PREPARE_SNAPSHOT,
        &req,
        PREPARE_SNAPSHOT_READ_TIMEOUT,
    )?;
    match reply {
        SnapshotReply::Ok {
            manifest_path,
            run_uuid,
            ..
        } => Ok((PathBuf::from(manifest_path), run_uuid)),
        SnapshotReply::Err { message, .. } => {
            Err(CliError::Other(format!("PrepareSnapshot: {message}")))
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrepareSnapshotOutcome {
    pub manifest_path: PathBuf,
    pub run_uuid: String,
}

/// V3 PrepareSnapshot with is_tty + learn_mode.
pub fn prepare_snapshot_v3(
    sock: &Path,
    cwd: &Path,
    is_tty: bool,
    learn_mode: bool,
) -> Result<PrepareSnapshotOutcome, CliError> {
    let req = PrepareSnapshot::new_v3(cwd.display().to_string(), is_tty, learn_mode);
    // WR-11: 150s read timeout (vs the default 5s) so a legitimate
    // first-run shallow clone (up to ~78s for GHSA on Apple Silicon
    // per RESEARCH.md Pitfall 1, with the daemon's 120s ceiling)
    // doesn't surface as DaemonUnreachable. The daemon's own fetch
    // deadline still fires first on a real timeout, producing a clean
    // SnapshotReply::Err("feed fetch: ...").
    let reply: SnapshotReply = send_tagged_request_with_read_timeout(
        sock,
        TAG_PREPARE_SNAPSHOT,
        &req,
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
            Err(CliError::Other(format!("PrepareSnapshot V3: {message}")))
        }
    }
}

/// v0.3 tag 0x09: request daemon status.
pub fn status_request(sock: &Path) -> Result<guard_ipc::StatusReply, CliError> {
    let req = guard_ipc::Status::new();
    send_tagged_request(sock, TAG_STATUS, &req)
}

/// v0.3 tag 0x0B: insert a user rule into the daemon's rule store.
/// Requires biometric authentication (Touch ID / password) before sending.
pub fn insert_user_rule_request(
    sock: &Path,
    kind: &str,
    match_type: &str,
    pattern: &str,
    reason: &str,
) -> Result<i64, CliError> {
    let bio_reason = format!("Stentorian Guard: {kind} rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let req = InsertUserRule {
        schema_version: guard_ipc::IPC_SCHEMA_V3,
        kind: kind.into(),
        match_type: match_type.into(),
        pattern: pattern.into(),
        reason: reason.into(),
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

/// Clear install_artifacts rows for the given
/// kinds. Invoked by `uninstall::components::remove_*` helpers after their
/// on-disk teardown so the daemon's view of installed artifacts matches
/// reality. Errors are surfaced as `CliError::Other`; callers typically
/// ignore them (best-effort cleanup — the daemon may be shutting down
/// concurrently with the global-remove path).
///
/// Returns the row count removed by the daemon (sum of per-kind delete
/// results).
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
pub fn disable_curated_rule_request(
    sock: &Path,
    pattern: &str,
    reason: &str,
) -> Result<(), CliError> {
    let bio_reason = format!("Stentorian Guard: disable curated rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let req = DisableCuratedRule::new(pattern, reason);
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
pub fn enable_curated_rule_request(sock: &Path, pattern: &str) -> Result<bool, CliError> {
    let bio_reason = format!("Stentorian Guard: re-enable curated rule for {pattern}");
    if !crate::biometric::authenticate(&bio_reason) {
        return Err(CliError::Other(
            "biometric authentication required to modify rules".into(),
        ));
    }
    let req = EnableCuratedRule::new(pattern);
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
