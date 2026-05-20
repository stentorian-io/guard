## Project

**Sentinel** — free, open-source macOS supply-chain firewall. Default-deny outbound network for package-install subtrees via DYLD injection. See [README.md](README.md) for user-facing docs, [CONTRIBUTING.md](CONTRIBUTING.md) for architecture, crate map, tech stack, IPC protocol, and build/test instructions.

**Core Value:** When a compromised package tries to phone home during install, Sentinel blocks it cold and tells the user what happened. Every other feature serves this.

### Agent-Relevant Constraints

- **Platform**: macOS only (v1). DYLD injection mechanism.
- **Privilege**: no root required; daemon runs as user
- **Performance**: hook overhead < 100us per intercepted call (in-process cache, no IPC on hot path)
- **Privacy**: no telemetry, no upstream submissions; threat-intel pull only
- **Fail-closed**: any error in snapshot/HMAC/IPC -> deny all network
- **panic=abort workspace-wide**: cdylib must not unwind through foreign C++ frames. Cannot use `catch_unwind`.
- **Bypass acknowledgement**: defense-in-depth, not a sandbox. Hardened-runtime binaries and raw syscalls can escape.

### Key Paths

- Curated trusted network rules: `crates/sentinel-core/data/trusted-registry-*.yaml`
- Curated malicious/suspicious network rules: `crates/sentinel-core/data/{malicious,suspicious}-*.yaml`
- Daemon migrations: `crates/sentinel-daemon/migrations/`
- E2E tests: `crates/sentinel-e2e/tests/`
- E2E fixtures: `crates/sentinel-e2e/fixtures/`
- CI workflow: `.github/workflows/validation.yml`
- Man pages: `docs/sentinel.1.md`, `docs/sentineld.8.md`

### Policy Evaluation Flow

1. CLI sends `PrepareSnapshot` IPC -> daemon merges rules -> CBOR snapshot (HMAC-signed)
2. CLI spawns child with `DYLD_INSERT_LIBRARIES` + snapshot path
3. Hook `#[ctor]` loads snapshot, captures libc symbols via `RTLD_NEXT`
4. On `connect()`/`sendto()`/etc.: `decide_for_sockaddr()` -> cache -> `evaluate_policy()` (CuratedAllow -> ConfirmedDeny -> UserDeny -> UserAllow -> SuspectDeny -> DefaultDeny)
5. Cache miss -> `Resolve` IPC to daemon for DNS -> cache -> re-evaluate
6. Deny + TTY -> prompt channel -> user decision -> persist to SQLite

### Version History

| Tag | Key Features |
|---|---|
| v0.1 | Hook hello-world, basic IPC, curated allowlist |
| v0.2 | ForkEvent/ExecEvent IPC, per-run snapshots, OSV/GHSA feed system, benchmarks |
| v0.3 | Prompt channel, install artifacts, JSONL logging, persistence watcher, PID-reuse guard |
| v0.4 | Watchdog, HMAC-SHA256 integrity, exec blocking, lockfile extraction, persistence-path monitoring |
| v0.5 | macOS 26+ dyld crash fix, getaddrinfo interpose via daemon-proxied DNS |
| v0.6 | Prompt timeout, E2E test modernization |
| v0.7 | Gap-detector wiring, background feed refresh, codesign peer auth, SpscRing fix |
| v0.8 | Man pages, install guide, changelog |
| v0.9 | CLI cleanup, auto-spawn daemon on demand |

**Current:** v0.9 shipped. Next: **v1.0** — Homebrew Formula, signing/notarization, first public release.

## Conventions

Conventional commits scoped by subsystem: `feat(hook):`, `fix(daemon):`, `test(e2e):`, `docs(bench):`, `chore:`

See [CONTRIBUTING.md](CONTRIBUTING.md) for full conventions (error handling, testing, IPC protocol, code style).
