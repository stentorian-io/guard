# Hot-Path Benchmark Report

Stentorian Guard's performance guarantee is that a cache-hit network decision in
the wrapped process resolves in under 100 microseconds without IPC.

That guarantee matters because the hook runs inside every wrapped process. Once
a destination has been resolved into the in-process policy cache, repeated
network calls should not pay daemon round trips, DNS lookups, prompt handling,
or filesystem I/O.

## Binding Budget

The binding budget is:

| measurement | budget |
|---|---:|
| cache-hit p99 | 100,000 ns |

The budget is enforced against the `decide_for_sockaddr` cache-hit benchmark.
The budget value lives as `CACHE_HIT_BUDGET_NS` near the top of the benchmark
runner script. If an intentional change needs a higher budget, update that
constant in the same PR and explain why the new number is acceptable.

## What Is Measured

The cache-hit benchmark measures the hook's libc decision path for an IPv4
socket address. It exercises address decoding, cache access, and policy
evaluation against a realistic allowlist snapshot. It does not contact the
daemon and does not perform live network I/O.

The live-wrap benchmark is a context measurement. It wraps a real Node.js
process and measures repeated connections to a curated registry host. That
number includes the surrounding system effects of a real wrapped process, so it
is reported for visibility but is not the hard budget gate.

## Regression Gates

CI runs the deterministic cache-hit benchmark on macOS and fails when p99
exceeds the 100 microsecond budget.

CI also records benchmark trend data and alerts on large relative regressions.
A relative regression can be accepted by applying the
`accepted-hot-path-regression` PR label, but that label does not bypass the hard
p99 budget. A hard-budget regression must be accepted by changing the budget
constant in the benchmark runner, which leaves a normal code-review diff.

The local pre-push hook runs the same deterministic cache-hit benchmark after
the E2E checks on macOS.

## Reproducing Locally

Run the full local benchmark report:

```sh
./scripts/bench-hot-path.sh
```

Run only the deterministic cache-hit gate used by CI and pre-push:

```sh
./scripts/bench-hot-path.sh --cache-hit-only --enforce-cache-hit-budget
```

The runner prints a markdown summary with machine, operating system, Rust
version, git SHA, cache-hit p99, and live-wrap p99 when the live-wrap benchmark
is enabled.

## Current Reference Result

The implementation that introduced CI gating produced this local cache-hit
result on an Apple Silicon MacBook Air:

| machine | RAM | macOS | rustc | cache-hit p99 |
|---|---:|---|---|---:|
| MacBookAir10,1 | 16 GB | 26.5 | 1.95.0 | 24,879 ns |

This reference result is not itself the guarantee. The maintained guarantee is
the enforced p99 budget above.
