# Sentinel

**Free, open-source macOS supply-chain firewall.**

Default-deny outbound network enforcement for package-install subtrees.
When a compromised dependency tries to phone home during `npm install`,
`pip install`, or `cargo build`, Sentinel blocks it cold and tells you
what happened.

[![CI](https://github.com/anthropics/sentinel/actions/workflows/validation.yml/badge.svg)](https://github.com/anthropics/sentinel/actions/workflows/validation.yml)

> **Status:** pre-release (v0.9). Core enforcement works end-to-end.
> Build from source; packaged distribution coming in v1.0.

## How it works

```sh
sentinel wrap npm install
```

Sentinel wraps your command via DYLD library injection. Every outbound
network call from the process tree is checked against a multi-tier policy:

1. **Curated Allow** — package registries and CDNs (built-in)
2. **User Allow** — personal allow/deny decisions
3. **Curated Deny** — known-malicious hosts from OSV/GHSA threat-intel feeds
4. **Default Deny** — everything else is blocked (or prompts in TTY mode)

No root privileges required. No kernel extensions. No system extension.
No manual setup — the daemon auto-starts on first use.

## Quick start

```sh
# Build from source
git clone https://github.com/anthropics/sentinel.git
cd sentinel
cargo build --workspace --release

# Protect a package install (daemon auto-starts on first use)
sentinel wrap npm install

# Learn mode — record what a clean install talks to
sentinel wrap --learn npm install

# Review blocked connections
sentinel status denials <run-uuid>
sentinel status review
```

See the [install guide](docs/INSTALL.md) for detailed setup instructions.

## Usage

### Wrapping commands

```sh
sentinel wrap npm install                    # npm
sentinel wrap pip install -r requirements.txt  # pip
sentinel wrap cargo build                     # cargo
```

Any command works — Sentinel wraps the entire process tree.

### Learn mode

Build a baseline of expected network destinations for a known-clean project:

```sh
sentinel wrap --learn npm install
```

This records all contacted hosts for future installs.

### Status and review

```sh
sentinel status                # daemon health, hook integrity, feed freshness
sentinel status --verbose      # detailed output
sentinel status --json         # machine-readable output
sentinel status logs --follow  # stream forensic log
sentinel status rules          # list active policy rules
```

## Architecture

```text
sentinel wrap <cmd>   sentineld (auto-spawned)        libsentinel_hook.dylib
┌──────────┐          ┌───────────────────┐           ┌──────────────────────┐
│ CLI      │          │ IPC server        │           │ DYLD-injected cdylib │
│          │          │ (Unix socket)     │           │                      │
│ ensure   │          │                   │           │ ctor: load snapshot  │
│ daemon   │ ──IPC──→ │ handlers:         │           │ interpose:           │
│          │          │  prepare_snapshot  │           │  socket/connect/     │
│ prepare  │          │  resolve (DNS)    │           │  bind/listen/send/   │
│ snapshot │          │  prompt_channel   │           │  getaddrinfo/        │
│          │          │  insert_user_rule │           │  exec*/fork/vfork/   │
│ spawn    │          │  status/rules/... │           │                      │
│ child    │          │                   │           │ hot path:            │
│ w/ DYLD  │          │ feed system:      │           │  decide_for_sockaddr │
│          │          │  gix fetch → OSV  │           │  → cache hit: <100µs│
│ wait +   │          │  parse → SQLite   │           │  → cache miss: IPC  │
│ report   │          │                   │           │    Resolve → daemon  │
└──────────┘          │ log writer: JSONL │           │                      │
                      │ process tree      │           │ fail-closed on:      │
                      │ snapshot GC       │           │  corrupt snapshot    │
                      │ persistence watch │           │  IPC timeout (250ms) │
                      └───────────────────┘           │  HMAC mismatch       │
                                                      └──────────────────────┘
```

**Key properties:**

- Hook overhead < 100 µs per intercepted call (in-process cache lookup, no IPC on hit)
- Fail-closed: any error in snapshot, HMAC, or IPC → deny all network
- HMAC-SHA256 signed snapshots prevent tamper
- Kernel audit-token IPC authentication
- JSONL forensic logging to `~/Library/Logs/Sentinel/`

See [docs/BENCH.md](docs/BENCH.md) for performance methodology and numbers.

## Workspace crates

| Crate | Type | Purpose |
|---|---|---|
| `sentinel-cli` | bin | CLI entry point |
| `sentinel-daemon` | bin | `sentineld` — IPC server, policy engine, feed fetcher |
| `sentinel-hook` | cdylib | `libsentinel_hook.dylib` — DYLD-injected interposition |
| `sentinel-core` | lib | Domain types, policy evaluator, snapshot codec |
| `sentinel-ipc` | lib | CBOR wire protocol, Unix socket transport |
| `sentinel-watchdog` | bin | Daemon liveness monitor |
| `sentinel-e2e` | tests | End-to-end test suites and benchmarks |

## Limitations

This is a defense-in-depth layer, not a sandbox:

- **Hardened-runtime binaries** (`/bin/bash`, system tools) reject DYLD
  injection — Sentinel blocks exec into them from wrapped subtrees instead
- **Raw syscalls** bypass libc interposition — not a realistic supply-chain
  attack vector (packages use libc)
- **macOS only** in v1; requires macOS 14+ (Sonoma) on Apple Silicon or Intel

## Documentation

- [Install guide](docs/INSTALL.md) — build, setup, and troubleshooting
- [Benchmarks](docs/BENCH.md) — performance methodology and reference numbers
- [Changelog](CHANGELOG.md) — version history
- `man sentinel` — CLI reference (after install)
- `man sentineld` — daemon reference (after install)

## Contributing

Contributions welcome. This project uses:

- **Rust** (edition 2024, stable toolchain)
- **Conventional commits** — `feat(hook):`, `fix(daemon):`, `test(e2e):`, etc.
- **CI validation** — PRs must pass the E2E test suite on macOS-14

```sh
# Run the full test suite
cargo test --workspace --release

# Run just the E2E validation tests
cargo test -p sentinel-e2e --release
```

## License

License TBD before v1.0 release.
