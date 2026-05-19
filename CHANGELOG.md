# Changelog

All notable changes to Sentinel are documented in this file.
This changelog is generated from [conventional commits](https://www.conventionalcommits.org/).

## [0.9] — 2026-05-18

### Features
- **cli:** Replace external-subcommand catch-all with explicit `sentinel wrap`
- **cli,daemon:** Remove install/setup/trust policy and project config
- **cli,daemon:** Auto-spawn daemon on demand, remove LaunchAgent/DevInstall
- **core,daemon,cli:** Remove .sentinel.toml project-config feature

### Bug Fixes
- **e2e,cli,daemon:** Unblock prompt teardown and stabilize CI e2e

## [0.8] — 2026-05-14

### Documentation
- Add man pages for sentinel(1) and sentineld(8)
- Add install guide with build, setup, and troubleshooting
- Overhaul README to standard OSS structure, update roadmap

## [0.7] — 2026-05-13

### Features
- **daemon,cli,e2e:** Production hardening

## [0.6] — 2026-05-12

### Features
- **daemon:** Add kqueue-based persistence-path watcher
- **hook:** Re-enable getaddrinfo interpose via daemon-proxied DNS
- **daemon:** Add policy gate to Resolve IPC handler
- **daemon:** Skip prompt for policy-allowed hosts in TTY resolve path
- **hook:** Enforce FAIL_CLOSED in getaddrinfo interpose
- **daemon,e2e:** Prompt timeout and E2E test modernization

### Bug Fixes
- **hook,e2e:** Errno ordering and test harness improvements
- **e2e:** Use local feed fixtures for CI-compatible release builds

### Documentation
- Align CLAUDE.md and README.md with current Rust/DYLD codebase

## [0.5] — 2026-05-11

### Features
- **watchdog:** Add sentinel-watchdog crate with daemon liveness monitoring
- **integrity:** HMAC-SHA256 snapshot integrity scheme
- **hook:** Binary self-integrity verification at load time
- **hook:** Anti-detection getenv interposition
- **cli:** Add `sentinel repair` and `sentinel unwrap-all` commands

### Bug Fixes
- **hook:** Resolve macOS 26+ crash from dyld init-order conflicts

## [0.4] — 2026-05-10

### Features
- **hook:** Expand interpose surface with send/write/writev hooks and raw syscall backend
- **hook:** Block exec of network-capable hardened-runtime binaries
- **cli:** Ambient shell wrapping via init.sh package-manager functions
- **hook:** Monitor open/openat to macOS persistence paths
- **cli:** Add `sentinel status persistence` subcommand
- **hook:** OS-version-aware persistence-path matrix
- **core:** Add lockfile registry extraction and snapshot integration

## [0.3] — 2026-05-10

### Features
- **ipc:** Add DenyNotify message for hook-to-daemon denial forensics

### Bug Fixes
- **core,daemon:** Ancestor-walk $HOME boundary shared SQLite reader
- **daemon,hook:** Close PID-reuse race via TASK_AUDIT_TOKEN pidversion cross-check

## [0.2] — 2026-05-09

### Features
- **cli:** Root-default-wrap parser surface (Cmd::External + --learn)
- **daemon,ipc:** Add ListRules/ListTrust/IsTrusted/DeleteInstallArtifacts wire types
- **daemon,ipc:** Add daemon handlers for ListRules/ListTrust/IsTrusted/DeleteInstallArtifacts
- **daemon,ipc:** Wire MessageTag 0x0E/0x0F/0x10/0x11 dispatch arms
- **cli:** Add install/drift module + tty::confirm consolidated helper
- **cli:** Factor uninstall into per-component helpers + run_remove dispatch
- **cli:** Add list_rules/list_trust/is_trusted ipc_client request fns
- **cli:** Add status::{rules,trust,denials,review} submodules
- **cli:** Add setup::run_setup dispatch + wire install --reinstall
- **cli:** Atomic clap surface cutover — Cmd::Setup + Cmd::Status hard-cut
- **cli:** First-trust prompt in run_orchestrator + delete approve.rs + trim trust_policy.rs

### Bug Fixes
- **cli:** Reject --learn with named verbs
- **cli:** Detect stdin EOF in status review to prevent infinite loop
- **cli:** Narrow --project filter to trusted-toml rules only
- **cli:** Drift detection — key-by-key plist compare to avoid false drifts
- **cli:** Clean init_script from daemon-only remove path
- **cli:** Reject misordered status --json/--verbose with EX_USAGE

### Documentation
- Drop 'run' from README usage example
- Add Performance section + docs/BENCH.md cross-link to README

## [0.1] — 2026-05-08

Initial release.


