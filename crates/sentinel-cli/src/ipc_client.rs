//! Connect to the daemon socket, send messages, await Replies.
//!
//! ISS-08 remediation: explicit 5-second connect timeout (rather than relying
//! on the OS-default connect(2) timeout, which is implementation-defined on
//! macOS for unix-domain sockets). We achieve this with the documented Rust
//! pattern: build a non-blocking socket via the `socket2` crate (already in
//! the workspace), call `connect_timeout`, then convert to a blocking
//! `UnixStream` for the read/write phase.

use crate::CliError;
use sentinel_core::AuditToken;
use sentinel_ipc::frame::{read_frame, write_frame};
use sentinel_ipc::{
    DeleteInstallArtifacts, DeleteInstallArtifactsReply,
    FeedWarning, InsertUserRule, InsertUserRuleReply, InstallArtifact,
    ListRules, ListRulesReply, PrepareSnapshot, ReadInstallArtifacts,
    ReadInstallArtifactsReply, RegisterRoot, Reply, RuleRow, SnapshotReply,
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Tag bytes — must match plan 02-04's MessageTag values exactly. The dylib
// uses the same values in `sentinel_hook::ipc_client`.
const TAG_PREPARE_SNAPSHOT: u8 = 0x02;
const TAG_STATUS: u8 = 0x09;
pub(crate) const TAG_PROMPT_CHANNEL_INIT: u8 = 0x0A;
const TAG_INSERT_USER_RULE: u8 = 0x0B;
const TAG_READ_INSTALL_ARTIFACTS: u8 = 0x0C;
const TAG_LIST_RULES: u8 = 0x0E;
const TAG_DELETE_INSTALL_ARTIFACTS: u8 = 0x11;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// WR-11 fix: PrepareSnapshot's read timeout must EXCEED the daemon's
/// `fetch_feeds_blocking` worst-case deadline. The daemon allows up to
/// 120s for first-run shallow clones (`FETCH_DEADLINE_FIRST_RUN`) +
/// 60s for incremental fetches; if the CLI tripped its 5s read timeout
/// FIRST, the user would see `DaemonUnreachable("read reply: ...")`
/// while the daemon was actually working hard on a legitimate fetch.
///
/// 150s gives the daemon's 120s ceiling room to either complete OR
/// produce a graceful `feed fetch timeout` SnapshotReply::Err. If the
/// daemon's deadline propagation itself broke and the fetch hung
/// past 150s, the CLI's read timeout fires (defense-in-depth) and
/// produces DaemonUnreachable — but THAT is a true daemon-side bug,
/// not a normal-operation timeout.
const PREPARE_SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(150);

/// Connect to the daemon socket with an explicit 5s connect timeout. Returns
/// a blocking `UnixStream` on success. ISS-08: the prior implementation used
/// `UnixStream::connect` which has no documented timeout and could block
/// indefinitely on certain Darwin states.
pub(crate) fn connect_with_timeout(sock: &Path) -> Result<UnixStream, CliError> {
    let addr = SockAddr::unix(sock)
        .map_err(|e| CliError::DaemonUnreachable(format!("sockaddr({}): {e}", sock.display())))?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)
        .map_err(|e| CliError::DaemonUnreachable(format!("socket: {e}")))?;
    socket
        .connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| CliError::DaemonUnreachable(format!("connect({}): {e}", sock.display())))?;
    socket.set_read_timeout(Some(READ_TIMEOUT)).ok();
    socket.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
    // WR-02: socket2 0.5+ implements `From<Socket> for UnixStream` on Unix.
    // The previous `into_raw_fd` + `unsafe { from_raw_fd }` dance was correct
    // in the happy path but had no guard against future fallible code being
    // inserted between the two operations — `into_raw_fd` consumes the
    // Socket (so its Drop no longer runs) and a panic before `from_raw_fd`
    // would leak the fd. The safe `Into` conversion has no such risk.
    let stream: UnixStream = socket.into();
    Ok(stream)
}

/// ISS-08 remediation: connect-only liveness probe sent BEFORE spawning the
/// wrapped child. If the daemon is unreachable, the CLI exits 70 (EX_SOFTWARE)
/// without having forked an unprotected child — keeping T-01-08-06's promise.
///
/// Why connect-only (no frame sent):
///   - The socket file at `sock` is bound by the daemon (`UnixListener::bind`
///     in plan 05 task 2). A non-running daemon yields ECONNREFUSED or ENOENT,
///     so a successful `connect_timeout` IS sufficient liveness evidence.
///   - Sending a frame would require defining a new wire message type
///     (avoided: keeps the IPC schema minimal and forward-compatible — no new
///     enum variants in plan 04's messages.rs are needed).
///   - Plan 05 task 2's `ipc_server::handle` tolerates the resulting EOF on
///     `read_frame` as a benign liveness probe (no state change, no panic,
///     idle log line at debug level).
///
/// The stream is dropped immediately on success; the daemon's `accept()` sees
/// a connect+immediate-close, which is the documented benign liveness path.
pub fn probe_daemon_alive(sock: &Path) -> Result<(), CliError> {
    let _stream = connect_with_timeout(sock)?;
    // Stream dropped here; the daemon will see EOF on its first read_frame
    // and treat it as a benign liveness check (plan 05 task 2 contract).
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

/// Send a Phase 2 tagged frame: `[1-byte tag][4-byte BE length][CBOR body]`,
/// then read the daemon's tag-echoed reply: `[1-byte tag][4-byte BE length][CBOR body]`.
///
/// Wire shape symmetry with:
///   - daemon-side:  `crates/sentinel-daemon/src/ipc_server.rs::write_tagged`
///   - dylib-side:   `crates/sentinel-hook/src/ipc_client.rs::send_tagged_and_recv_ack`
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
    // Override the per-stream read timeout if it differs from the default
    // already set by `connect_with_timeout`. `set_read_timeout` is a
    // best-effort; if it fails the request still proceeds (the CLI just
    // uses the previously-set 5s default).
    if read_timeout != READ_TIMEOUT {
        let _ = stream.set_read_timeout(Some(read_timeout));
    }
    stream
        .write_all(&[tag])
        .map_err(|e| CliError::DaemonUnreachable(format!("tag write: {e}")))?;
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

/// Send `PrepareSnapshot { cwd }` BEFORE posix_spawn so the daemon merges
/// curated YAML + SQLite rules, writes a per-run snapshot to
/// `${state_dir}/runs/{uuid}.cbor`, and returns the manifest path. The CLI
/// then sets that manifest path as `SENTINEL_SNAPSHOT_MANIFEST` in the
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

/// Outcome of a PrepareSnapshot v3 call. Phase 4 plan 04-03 added the
/// `feed_warnings` field so callers (run_orchestrator) can surface non-fatal
/// post-fetch parse problems inline on stderr after the reply.
#[derive(Debug, Clone)]
pub struct PrepareSnapshotOutcome {
    pub manifest_path: PathBuf,
    pub run_uuid: String,
    pub feed_warnings: Vec<FeedWarning>,
}

/// V3 PrepareSnapshot with is_tty + learn_mode.
/// Used by run_orchestrator instead of prepare_snapshot.
///
/// Returns `PrepareSnapshotOutcome` carrying `feed_warnings` from the
/// V4-shaped reply.
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
            feed_warnings,
            ..
        } => Ok(PrepareSnapshotOutcome {
            manifest_path: PathBuf::from(manifest_path),
            run_uuid,
            feed_warnings,
        }),
        SnapshotReply::Err { message, .. } => {
            Err(CliError::Other(format!("PrepareSnapshot V3: {message}")))
        }
    }
}

/// Phase 3 tag 0x09: request daemon status.
pub fn status_request(sock: &Path) -> Result<sentinel_ipc::StatusReply, CliError> {
    let req = sentinel_ipc::Status::new();
    send_tagged_request(sock, TAG_STATUS, &req)
}

/// Phase 3 tag 0x0B: insert a user rule into the daemon's rule store.
pub fn insert_user_rule_request(
    sock: &Path,
    kind: &str,
    match_type: &str,
    pattern: &str,
    reason: &str,
) -> Result<i64, CliError> {
    let req = InsertUserRule {
        schema_version: sentinel_ipc::IPC_SCHEMA_V3,
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

/// Phase 3 tag 0x0C: read install artifacts from the daemon (D-62 preferred path).
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
pub fn list_rules_request(
    sock: &Path,
    include_builtins: bool,
) -> Result<Vec<RuleRow>, CliError> {
    let req = ListRules::new(include_builtins);
    let reply: ListRulesReply = send_tagged_request(sock, TAG_LIST_RULES, &req)?;
    match reply {
        ListRulesReply::Ok { rules, .. } => Ok(rules),
        ListRulesReply::Err { message, .. } => {
            Err(CliError::Other(format!("ListRules: {message}")))
        }
    }
}
