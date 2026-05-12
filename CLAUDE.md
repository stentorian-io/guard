## Project

**Sentinel**

Sentinel is a free, open-source macOS supply-chain firewall that enforces default-deny on outbound network connections from package-install subtrees. The user runs `sentinel npm install …` (or `pip`, `cargo`, etc.) and Sentinel sandboxes that subtree's network egress — registries are allowed, anything else is denied or surfaces an interactive prompt. v1 is process-tree-only and uses DYLD library injection (no system extension, no kernel components). Whole-machine mode is deferred to v2.

**Core Value:** **When a compromised package tries to phone home during install, Sentinel blocks it cold and tells the user what happened.** That's the one thing that must work. Every other feature serves this.

### Constraints

- **Platform**: macOS only in v1
- **Tech stack**: Rust everywhere — CLI, daemon (`sentineld`, user-level LaunchAgent), and the `libsentinel_hook.dylib` injected into wrapped processes
- **Enforcement mechanism**: DYLD library injection via `DYLD_INSERT_LIBRARIES` — covers the libc-using real-world supply-chain attack class but not hardened-runtime children or raw-syscall malware
- **Privilege**: no root/admin required for enforcement; daemon runs as the user
- **Privacy**: Sentinel is an anti-exfiltration tool — it cannot itself become a telemetry pipe. Threat-intel feed pulls only; no upstream submissions in v1; no analytics in the daemon
- **UX**: terminal-only — no GUI, no menu bar, no web dashboard in v1
- **Performance**: hook overhead must be negligible — under 100µs per intercepted call (in-process lookup against an mmap'd snapshot, no IPC on the hot path)
- **Bypass acknowledgement**: this is a defense-in-depth layer, not a sandbox — sufficiently advanced malware can use raw syscalls or exec into hardened binaries to escape. Sentinel must catch the realistic supply-chain attack class, not the theoretical 100%

## Technology Stack

| Layer | Implementation | Notes |
|---|---|---|
| Language | **Rust** (edition 2024, MSRV 1.85) | All crates: CLI, daemon, hook dylib, core, IPC, watchdog, E2E |
| Build | **Cargo workspaces** | 11 member crates; release profile: LTO thin, codegen-units=1, panic=abort, strip symbols |
| Enforcement | **DYLD_INSERT_LIBRARIES** → `libsentinel_hook.dylib` (cdylib) | Interposes libc network/exec/fork/open calls via `dlsym(RTLD_NEXT, ...)` |
| IPC | **Unix domain socket** + length-prefixed **CBOR** frames | Peer auth via `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` (kernel-sourced audit token) |
| Daemon | **sentineld** — sync 32-thread worker pool, bounded queue (64) | LaunchAgent with KeepAlive=true; watchdog crate monitors liveness |
| Persistence | **rusqlite** (bundled SQLite) | Migrations in `crates/sentinel-daemon/migrations/`; stores rules, feed IOCs, install artifacts |
| CLI parsing | **clap 4.6** (derive) | Subcommands: run (external), setup, repair, unwrap-all, status |
| Serialization | **ciborium** (CBOR), **serde** | Snapshot format, IPC wire protocol |
| Logging | **tracing** + **tracing-subscriber** | Daemon logs; JSONL forensic log to `~/Library/Logs/Sentinel/` |
| Threat-intel | **gix** (git2 in Rust) | Clones ossf/malicious-packages + github/advisory-database repos; OSV JSON parsing |
| Integrity | **HMAC-SHA256** snapshot signing | Hook verifies snapshot integrity at load time; self-check of hook binary hash |
| Process tracking | **audit_token** + **pidversion** | Fork/exec IPC events; PID-reuse guard via TASK_AUDIT_TOKEN |

### Key Dependencies

**Production:** libc, ciborium, serde, nix, clap, rusqlite, uuid, signal-hook, memmap2, socket2, tracing, plist, ctor, gix, toml, dialoguer, chrono, notify, flate2, semver, url, walkdir

**Dev/Test:** criterion, tempfile, assert_cmd, predicates, sha2, hmac, rand

## Architecture

```
sentinel <cmd>        sentineld (LaunchAgent)         libsentinel_hook.dylib
┌──────────┐          ┌───────────────────┐           ┌──────────────────────┐
│ CLI      │          │ IPC server        │           │ DYLD-injected cdylib │
│          │ ──IPC──→ │ (Unix socket)     │           │                      │
│ prepare  │          │                   │           │ ctor: load snapshot  │
│ snapshot │          │ handlers:         │           │ interpose:           │
│          │          │  prepare_snapshot  │           │  socket/connect/     │
│ spawn    │          │  resolve (DNS)    │           │  bind/listen/send/   │
│ child    │          │  prompt_channel   │           │  getaddrinfo/        │
│ w/ DYLD  │          │  insert_user_rule │           │  exec*/fork/vfork/   │
│          │          │  trust_policy     │           │  posix_spawn/open    │
│ wait +   │          │  status/rules/... │           │                      │
│ report   │          │                   │           │ hot path:            │
└──────────┘          │ feed system:      │           │  decide_for_sockaddr │
                      │  gix fetch → OSV  │           │  → cache hit: <100µs│
                      │  parse → SQLite   │           │  → cache miss: IPC  │
                      │                   │           │    Resolve → daemon  │
                      │ log writer: JSONL │           │                      │
                      │ process tree      │           │ fail-closed on:      │
                      │ snapshot GC       │           │  corrupt snapshot    │
                      │ persistence watch │           │  IPC timeout (250ms) │
                      └───────────────────┘           │  HMAC mismatch       │
                                                      └──────────────────────┘
```

### Workspace Crates

| Crate | Type | Purpose |
|---|---|---|
| `sentinel-cli` | bin | CLI entry point — `sentinel <cmd>`, `sentinel setup`, `sentinel status`, `sentinel repair` |
| `sentinel-daemon` | bin | `sentineld serve` — IPC server, policy engine, feed fetcher, log writer |
| `sentinel-hook` | cdylib | `libsentinel_hook.dylib` — DYLD-injected interposition library |
| `sentinel-core` | lib | Domain types: ProcessIdentity, AllowlistEntry, Snapshot (CBOR), policy evaluator, lockfile parser |
| `sentinel-ipc` | lib | IPC wire protocol: CBOR frame codec, Unix socket transport, peer audit-token auth |
| `sentinel-watchdog` | bin | Daemon liveness monitor — ping every 500ms, SIGTERM→SIGKILL on 2 consecutive misses |
| `sentinel-e2e` | tests | 56 E2E test suites + benchmark harness binaries |

### Policy Evaluation Flow

1. CLI sends `PrepareSnapshot` IPC → daemon fetches feeds, merges curated + project + user rules → returns CBOR snapshot (HMAC-signed)
2. CLI spawns child with `DYLD_INSERT_LIBRARIES=libsentinel_hook.dylib` + `SENTINEL_SNAPSHOT_MANIFEST=<path>`
3. Hook `#[ctor]` loads snapshot, captures original libc symbols via `RTLD_NEXT`
4. On `connect()` / `sendto()` / etc.: `decide_for_sockaddr()` → in-process cache → `evaluate_policy()` (tier walk: CuratedAllow → ProjectAllow → UserAllow → CuratedDeny → default Deny)
5. Cache miss → `Resolve` IPC to daemon for DNS → cache result → re-evaluate
6. Deny + TTY → prompt channel → user Allow/Deny → persist to SQLite

### Rule Tiers (precedence order)

1. **CuratedAllow** — built-in allowlist (`crates/sentinel-core/data/allowlist.yaml`): package registries, CDNs
2. **ProjectAllow** — `.sentinel.toml` in project tree (trust-gated)
3. **UserAllow** — user-created rules (via prompt or CLI)
4. **CuratedDeny** — threat-intel IOCs from OSV/GHSA feeds
5. **Default Deny** — everything else

### Known Limitations (v1 / DYLD approach)

- **Hardened-runtime binaries** (`/bin/bash`, `/usr/bin/python3`, system binaries) reject DYLD injection; hook cannot interpose them. Mitigated by exec-blocking hardened children from wrapped subtrees.
- **Raw syscalls** bypass libc interposition entirely. Not a realistic supply-chain attack vector (packages use libc).
- **macOS 26+** required a dyld init-order fix (v0.5); `open`/`openat` interposition disabled on 26+ (replaced with kqueue watcher).
- **panic=abort workspace-wide** — gix panics terminate the daemon (launchd restarts it). Cannot use catch_unwind because cdylib must not unwind through foreign C++ frames.

## Version History

| Tag | Milestone | Key Features |
|---|---|---|
| v0.1 | Foundations | Hook hello-world, basic IPC, curated allowlist |
| v0.2 | Feed + Snapshot | ForkEvent/ExecEvent IPC, per-run snapshots, OSV/GHSA feed system, benchmarks |
| v0.3 | Prompt + Install | Prompt channel (dedup 5s), install artifacts, JSONL logging, persistence watcher, PID-reuse guard |
| v0.4 | Hardening | Watchdog, HMAC-SHA256 snapshot integrity, exec blocking, lockfile extraction, persistence-path monitoring |
| v0.5 | Stability | macOS 26+ dyld crash fix, getaddrinfo interpose via daemon-proxied DNS, feed fixture CI compat |

**Current:** v0.5 shipped. Three milestones to v1.0:
- **v0.6 (M005):** Interactive prompting via daemon-proxied DNS — planned, not started
- **v0.7 (M006):** Production hardening (gap-detector wiring, background feed refresh, codesign peer auth, SpscRing fix, probe_self_test)
- **v1.0 (M007):** Distribution & docs (Homebrew Formula, release CI, man pages, install guide, changelog)

## CI

GitHub Actions workflow (`.github/workflows/validation.yml`):
- Runner: macOS-14
- Steps: checkout → Node 20 (non-hardened) → cargo cache → verify fixture SHA-256 → `cargo build --workspace --release` → 6 validation E2E tests (ua-parser-js demo, workers.dev edge case, 4 failure-mode tests)

## Conventions

### Commit Messages
Conventional commits scoped by subsystem: `feat(hook):`, `fix(daemon):`, `test(e2e):`, `docs(bench):`, `chore:`

### Error Handling
- Hook: fail-closed — any error in snapshot load, HMAC verify, or IPC timeout → deny all network
- Daemon: launchd KeepAlive restart on crash; feed panics (gix) are terminal but non-blocking to user
- CLI: structured error types via `thiserror`

### Testing
- Unit tests in each crate (`#[cfg(test)]` modules)
- Integration tests in `crates/*/tests/`
- E2E tests in `crates/sentinel-e2e/tests/` — spawn real daemon + hook, exercise full flow
- Benchmarks: criterion micro-benchmarks + E2E live-wrap bench (see `docs/BENCH.md`)

### IPC Protocol
- Schema versions: V1 (RegisterRoot — frozen), V2 (PrepareSnapshot/Prompt), V3 (Resolve/Status), V4 (ForkEvent/ExecEvent/DylibLoaded)
- Frame format: 4-byte big-endian length prefix + CBOR payload
- Auth: kernel-sourced audit token via `LOCAL_PEERTOKEN` socket option

### Project Config
- `.sentinel.toml` — per-project rules (boundary walk from cwd to find it)
- Trust gate: TTY prompt on first use; auto-trust in non-TTY (SHA-256 validated)
