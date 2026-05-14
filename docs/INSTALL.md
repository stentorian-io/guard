# Installing Sentinel

Sentinel is a macOS supply-chain firewall. This guide covers building from
source and getting Sentinel running on your machine.

## Prerequisites

- **macOS 14 (Sonoma) or later** — Intel or Apple Silicon
- **Rust toolchain** — stable channel (install via [rustup](https://rustup.rs/))
- **Git** — for cloning the repository

Verify your Rust installation:

```sh
rustc --version   # 1.85 or later
cargo --version
```

## Build from source

```sh
git clone https://github.com/anthropics/sentinel.git
cd sentinel
cargo build --workspace --release
```

The release binaries are placed in `target/release/`:

| Binary | Purpose |
|--------|---------|
| `sentinel` | CLI — wraps commands under enforcement |
| `sentineld` | Background daemon — manages policy, feeds, prompts |
| `sentinel-watchdog` | Daemon liveness monitor |
| `libsentinel_hook.dylib` | DYLD-injected interposition library |

## Install to PATH

Copy the binaries to a directory in your `$PATH`:

```sh
cp target/release/sentinel /usr/local/bin/
cp target/release/sentineld /usr/local/bin/
cp target/release/sentinel-watchdog /usr/local/bin/
cp target/release/libsentinel_hook.dylib /usr/local/lib/
```

Or add `target/release/` to your `$PATH` for development.

## Run setup

```sh
sentinel setup
```

This installs:

1. **LaunchAgent** — a plist at `~/Library/LaunchAgents/` that starts
   `sentineld` automatically and keeps it alive
2. **Shell integration** — marker blocks in your shell RC files (`.zshrc`,
   `.bashrc`) that add Sentinel to your environment

Setup is idempotent — running it again updates existing components without
duplication.

### Setup targets

Install only specific components:

```sh
sentinel setup daemon   # LaunchAgent only
sentinel setup shell    # Shell integration only
```

### Uninstall

```sh
sentinel setup --remove
```

This removes the LaunchAgent and shell integration marker blocks.

## Verify the install

Check that the daemon is running and the hook is intact:

```sh
sentinel status
```

A healthy install shows daemon connectivity, hook integrity, and feed
freshness. Use `--verbose` for detailed output or `--json` for machine-
readable output.

## First protected install

Wrap any package manager command with `sentinel`:

```sh
sentinel npm install
sentinel pip install -r requirements.txt
sentinel cargo build
```

Sentinel blocks all outbound connections except known package registries.
If an unknown host is contacted and you're in a terminal, you'll get an
interactive prompt to allow or deny.

### Learn mode

For a known-clean project, use learn mode to build a baseline of expected
network destinations:

```sh
sentinel --learn npm install
```

This auto-allows all destinations encountered and records them in
`.sentinel.toml` for future installs. Only use this on a project you trust.

### Review blocked connections

After a run, review what was blocked:

```sh
sentinel status denials <run-uuid>
sentinel status review <run-uuid>
```

The `review` subcommand walks you through each denial interactively so you
can create allow or deny rules.

## Configuration

### .sentinel.toml

Create a `.sentinel.toml` in your project root to define per-project rules:

```toml
[[allow]]
host = "api.example.com"
port = 443
reason = "Internal API"
```

On first use, Sentinel prompts you to trust the file (SHA-256 validated).

### Policy tiers

Sentinel evaluates rules in this order:

1. **Curated Allow** — built-in package registries and CDNs
2. **Project Allow** — rules from `.sentinel.toml`
3. **User Allow** — rules created via interactive prompts
4. **Curated Deny** — known-malicious hosts from threat-intel feeds
5. **Default Deny** — everything else

## Troubleshooting

### Daemon not running

```sh
sentinel status
```

If the daemon is not running, try:

```sh
sentinel repair
```

This re-derives integrity keys and re-bootstraps LaunchAgents.

### SIP strips DYLD_INSERT_LIBRARIES

macOS System Integrity Protection (SIP) strips `DYLD_INSERT_LIBRARIES`
from hardened-runtime binaries. This means system binaries like
`/bin/bash`, `/usr/bin/python3`, and `/usr/bin/curl` cannot be hooked.

Sentinel handles this by blocking `exec` calls to hardened-runtime children
from within wrapped process trees. Package managers (Node, Python, Cargo)
use their own non-hardened binaries for network operations, so enforcement
still covers the realistic supply-chain attack surface.

**Do not disable SIP.** Sentinel is designed to work with SIP enabled.

### Hardened-runtime binaries

If you see messages about skipped hardened-runtime binaries, this is
expected. Sentinel intercepts the parent process's network calls and blocks
exec into hardened children. The protection model is:

- `npm` / `node` — hooked (not hardened-runtime)
- `pip` / `python3` — hooked when using a non-system Python (e.g., pyenv, Homebrew)
- `cargo` — hooked (not hardened-runtime)
- `/usr/bin/curl` — not hooked (hardened-runtime, but exec is blocked from wrapped subtrees)

### Shell integration not working

If `sentinel` isn't available after setup, check that your shell RC file
contains the Sentinel marker block:

```sh
grep -A2 'sentinel' ~/.zshrc
```

If missing, re-run:

```sh
sentinel setup shell
```

Then restart your shell or source the RC file.

### Emergency escape hatch

If Sentinel is interfering with a critical operation:

```sh
sentinel unwrap-all -y
```

This immediately stops the daemon and watchdog and clears all tracked
process roots. Re-run `sentinel setup` when you're ready to re-enable
protection.

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SENTINEL_STATE_DIR` | Override state directory | `~/Library/Application Support/Sentinel/` |
| `SENTINEL_LOG_DIR` | Override log directory (daemon) | `~/Library/Logs/Sentinel/` |
| `RUST_LOG` | Logging verbosity | `warn` (CLI), `info` (daemon) |

## Further reading

- `man sentinel` — CLI reference
- `man sentineld` — daemon reference
- [docs/BENCH.md](BENCH.md) — performance benchmarks
