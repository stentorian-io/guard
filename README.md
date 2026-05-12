# Sentinel

Free, open-source macOS supply-chain firewall. Default-deny outbound network
enforcement inside `sentinel <command>` subtrees. Defends developer
laptops against compromised npm / pip / cargo / etc. dependencies.

**Status:** pre-release (v0.5). Core enforcement works — hook interposition,
daemon-proxied DNS, threat-intel feeds, interactive prompts, forensic logging.
Not yet distributed as a binary; build from source.

## How it works

```sh
sentinel npm install
```

Sentinel wraps the command via DYLD library injection. Every outbound network
call from `npm` and its children is checked against a multi-tier policy:

1. **Curated allow** — package registries, CDNs (built-in)
2. **Project rules** — `.sentinel.toml` in your repo
3. **User rules** — your personal allow/deny decisions
4. **Threat-intel deny** — known-malicious hosts from OSV/GHSA feeds
5. **Default deny** — everything else is blocked (or prompts in TTY mode)

## Quick start

```sh
# Build
cargo build --workspace --release

# Install (LaunchAgent + shell integration)
sentinel setup

# Use
sentinel npm install
sentinel pip install -r requirements.txt
sentinel cargo build

# Learn mode — record what a clean install talks to
sentinel --learn npm install

# Check what happened
sentinel status denials <run-uuid>
sentinel status review
sentinel status logs --follow
```

## Performance

Hook-overhead p99 is **< 100 µs on cache-hit** — in-process snapshot lookup,
no IPC on the hot path. See [docs/BENCH.md](docs/BENCH.md) for methodology
and reference numbers.

## Limitations

This is a defense-in-depth layer, not a sandbox:

- **Hardened-runtime binaries** (`/bin/bash`, system tools) reject DYLD injection — Sentinel blocks exec into them from wrapped subtrees instead
- **Raw syscalls** bypass libc interposition — not a realistic supply-chain attack vector
- **macOS only** in v1; requires Apple Silicon or Intel Mac

## License

License TBD before v1 release.
