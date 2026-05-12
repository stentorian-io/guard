# Sentinel

Free, open-source macOS supply-chain firewall. Default-deny outbound network
enforcement inside `sentinel <command>` subtrees. Defends developer
laptops against compromised npm / pip / cargo / etc. dependencies.

**Status:** pre-release; Phase 1 (foundations + hook hello-world).

## Quick start

```sh
cargo build --workspace --release
```

(Wrapped-command UX lands in plan 08; e2e smoke test in plan 09.)

## Performance

Sentinel's hook-overhead p99 budget is **< 100 µs on cache-hit** — the architectural
promise that "in-process snapshot lookup, no IPC on the hot path" is real. See
[docs/BENCH.md](docs/BENCH.md) for the methodology, reference-machine numbers,
and the one-command reproduction recipe (`./scripts/bench-hot-path.sh`).

## License

License TBD before v1 release.
