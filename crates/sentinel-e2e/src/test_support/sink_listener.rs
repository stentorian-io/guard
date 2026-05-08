//! Phase 5 plan 05-02: C2 sink redirect helper for validation tests.
//!
//! Two variants, exposed via `start_or_hosts(...)`:
//!
//!   1. **HostsRewriter** — rewrites `/etc/hosts` to point sink hostnames at
//!      127.0.0.1. Works for ALL ports without binding any (vendored
//!      preinstall.sh fires curls to whatever port the sanitized script
//!      specifies). Requires passwordless sudo (macos-14 GHA runner has it
//!      per RESEARCH §Pitfall 6). RAII Drop restores original /etc/hosts.
//!
//!   2. **SinkListener** — fallback when sudo is unavailable. Binds a TCP
//!      listener on 127.0.0.1:<port> and accepts-and-discards. Per RESEARCH
//!      §Security V-Information-Disclosure: 127.0.0.1 ONLY (never 0.0.0.0)
//!      and every accepted connection is logged for forensic review.
//!
//! Per CONTEXT D-02 triple-defense (2): even if Sentinel fails to block, the
//! network stack hits a 127.0.0.1 endpoint that is either non-listening
//! (NXDOMAIN-style ECONNREFUSED) or accept-and-discard. Real exfiltration is
//! impossible.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ===========================================================================
// HostsRewriter — /etc/hosts variant
// ===========================================================================

/// RAII rewriter for /etc/hosts. Constructor appends host->IP lines via `sudo
/// tee`; Drop restores the original bytes via `sudo tee`. Errors on Drop are
/// logged via `eprintln!` (Drop cannot panic).
pub struct HostsRewriter {
    saved: Vec<u8>,           // original /etc/hosts bytes for restore
    restored: AtomicBool,     // set true by explicit restore() so Drop is idempotent
}

impl HostsRewriter {
    /// Append `127.0.0.1 <host>` lines for every entry in `hosts`. Uses
    /// `sudo tee /etc/hosts` (passwordless on macos-14 GHA per Pitfall 6).
    pub fn new(hosts: &[&str]) -> io::Result<Self> {
        let original = std::fs::read("/etc/hosts").unwrap_or_default();
        let mut new_content = original.clone();
        new_content.push(b'\n');
        for host in hosts {
            let line = format!("127.0.0.1 {host}\n");
            new_content.extend_from_slice(line.as_bytes());
        }
        Self::write_via_sudo_tee(&new_content)?;
        Ok(Self { saved: original, restored: AtomicBool::new(false) })
    }

    /// Restore the original /etc/hosts bytes. Idempotent.
    pub fn restore(&self) -> io::Result<()> {
        if self.restored.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        Self::write_via_sudo_tee(&self.saved)
    }

    fn write_via_sudo_tee(bytes: &[u8]) -> io::Result<()> {
        let mut child = std::process::Command::new("sudo")
            .arg("tee").arg("/etc/hosts")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(bytes)?;
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("sudo tee failed: {status}")));
        }
        Ok(())
    }
}

impl Drop for HostsRewriter {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            // Drop cannot panic; log only (RESEARCH §Anti-Patterns).
            eprintln!("HostsRewriter::Drop failed to restore /etc/hosts: {e}");
        }
    }
}

// ===========================================================================
// SinkListener — localhost TCP variant (fallback when sudo unavailable)
// ===========================================================================

/// RAII localhost listener. Bind a TCP socket on 127.0.0.1:<port> and
/// accept-and-discard. Drop signals the accept thread to exit and joins.
pub struct SinkListener {
    pub addr: SocketAddr,
    accepted: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl SinkListener {
    /// Bind and start the accept thread. Pass `port = 0` for an ephemeral port
    /// (read it back via `.addr.port()`). Per the security gate, binds 127.0.0.1
    /// only — NEVER 0.0.0.0.
    pub fn start(port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let accepted: Arc<std::sync::Mutex<Vec<SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let accepted_clone = accepted.clone();
        let shutdown_clone = shutdown.clone();
        let handle = thread::spawn(move || {
            loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        // RESEARCH Security: log every accepted connection as a
                        // forensic artifact. eprintln! routes to test stderr.
                        eprintln!("[sink_listener] accepted from {peer}");
                        if let Ok(mut log) = accepted_clone.lock() {
                            log.push(peer);
                        }
                        // Drain a few bytes so the client sees data move,
                        // then drop the stream. Keep total drain bounded to
                        // 4 KiB to avoid a slowloris-shaped attacker keeping
                        // the test thread alive.
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                        let mut buf = [0u8; 1024];
                        let mut total = 0usize;
                        while total < 4096 {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => total += n,
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => return,
                }
            }
        });

        Ok(Self { addr, accepted, shutdown, handle: Some(handle) })
    }

    /// Snapshot of accepted-from peer addresses for forensic assertions.
    pub fn accepted_peers(&self) -> Vec<SocketAddr> {
        self.accepted.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl Drop for SinkListener {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ===========================================================================
// start_or_hosts — entry that picks the right variant
// ===========================================================================

/// Guard returned by `start_or_hosts`. Holds whichever variant fired so the
/// test gets a single RAII handle.
pub enum SinkGuard {
    Hosts(HostsRewriter),
    Listener(SinkListener),
}

/// Try the /etc/hosts variant first (covers all ports for all hostnames in
/// one shot). If the rewrite fails (sudo not available, /etc/hosts not
/// writable), fall back to a localhost listener on `fallback_port`.
///
/// Hosts are 127.0.0.1-redirected; listener accepts-and-discards. Either
/// way, no real C2 server is reachable.
pub fn start_or_hosts(
    hosts: &[&str],
    fallback_port: u16,
) -> io::Result<SinkGuard> {
    match HostsRewriter::new(hosts) {
        Ok(r) => Ok(SinkGuard::Hosts(r)),
        Err(e) => {
            eprintln!("[sink_listener] /etc/hosts rewrite failed ({e}); falling back to localhost listener");
            let l = SinkListener::start(fallback_port)?;
            Ok(SinkGuard::Listener(l))
        }
    }
}
