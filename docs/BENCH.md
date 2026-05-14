# Sentinel Hot-Path Benchmark

Methodology and reference numbers for Sentinel's `< 100µs` cache-hit hot-path
budget (VAL-03 / Phase 08).

The < 100µs claim defends Sentinel's architectural promise: **in-process snapshot
lookup, no IPC on the hot path**. Cache hits go through `decide_for_sockaddr →
with_cache(Mutex) → evaluate_policy(tier-walk)` entirely in the dylib. Cache
misses fall through to a Resolve IPC RTT, which is structurally milliseconds —
that is reported here as a context number with no fixed budget.

## Reference Machine

The reference numbers below were measured on:

- **Hardware:** MacBookAir10,1 — 16 GB
- **macOS:** 26.3.1
- **rustc:** 1.93.0 (254b59607 2026-01-19)
- **git SHA:** a27eafa
- **Date (UTC):** 2026-05-10T08:14:32Z

> Run `./scripts/bench-hot-path.sh` to populate these fields and the table
> below from your own machine. The first time the project measures on a new
> SKU, append a new row to the table rather than overwriting — Phase 08 D-35.

## Capture Procedure

The Numbers table and the Reference Machine block both ship with `TBD`
placeholders. The binding p99 number is intentionally human-curated by
the project author on a specific Apple Silicon machine (see CONTEXT D-33
and D-35); it is not a CI artifact. Anyone reproducing on their own M-series
Mac follows the same procedure to land an appendix row.

**Pre-flight (any dev machine, ~1 second):**

```sh
./scripts/bench-hot-path.sh --dry-run
```

This confirms the percentile-extraction greps still match the bench tool's
output shape. If `dry-run: ok` does not print, fix the runner script BEFORE
moving to the reference machine — the actual bench takes 30-60 seconds and
silently-broken extraction is the most common waste of that time.

**Capture (on the reference machine, ~60 seconds):**

```sh
./scripts/bench-hot-path.sh
```

The script (a) builds the workspace `--release`, (b) runs `cargo bench -p
sentinel-hook --bench cache_hit_hot_path` for the binding cache-hit p99,
(c) runs the `#[ignore]`-gated `cargo test -p sentinel-e2e --release --test
bench_hot_path_e2e -- --ignored --nocapture` for the context live-wrap p99,
and (d) prints a markdown summary block on stdout shaped like:

```
## Bench Summary

Paste the row below into docs/BENCH.md under the numbers table.

| machine | RAM | macOS | rustc | git SHA | date (UTC) | cache-hit p99 | live-wrap p99 |
|---------|-----|-------|-------|---------|------------|----------------|----------------|
| <hw.model> | <GB> | <productVersion> | <rustc -V> | <SHA> | <ISO> | <p99>ns | <p99>ns |
```

**Update (mechanical, ~30 seconds in the editor):**

1. Replace the `TBD` row in the `## Numbers` table with the row the runner
   printed.
2. Replace each `TBD-*` placeholder in `## Reference Machine` with the
   matching value (e.g., `TBD-MAC-MODEL` → `Mac15,3` from the printed
   `<hw.model>`).
3. Optionally delete this `## Capture Procedure` section once the binding
   number lands. (Keeping it is also fine — the procedure stays useful for
   re-runs on different SKUs.)
4. Commit with a message like
   `docs(bench): capture cache-hit p99 on <machine> reference run`.

**Cross-check:** the cache-hit p99 must be < 100,000 ns (i.e., < 100 µs)
for the v0.1 / v0.2 hot-path budget claim to hold. If the captured number
exceeds 100,000 ns, do NOT update the Numbers table; instead, surface the
regression as a phase-level concern — the methodology shipped in v0.2 is
sound, but the architectural claim would need re-evaluation.

## Numbers

| machine | RAM | macOS | rustc | git SHA | date (UTC) | cache-hit p99 | live-wrap p99 |
|---------|-----|-------|-------|---------|------------|----------------|----------------|
| MacBookAir10,1 | 16 GB | 26.3.1 | 1.93.0 | a27eafa | 2026-05-10 | 250 ns | — (live-wrap timed out; node unavailable) |

**cache-hit p99** is the BINDING number — the architectural promise. Target:
**< 100,000 ns (100 µs)**.

**live-wrap p99** is a CONTEXT number — measures wall-clock from `connect()`
call to TCP `'connect'` event for a wrapped node child looping
`net.connect(443, 'registry.npmjs.org')`. Includes Sentinel hook + cache-hit +
occasional Resolve-IPC cache-miss + TCP handshake to the real host. No fixed
budget; reported for transparency. (Phase 08 CONTEXT D-32.)

## Methodology

- **Bench harness:** [`criterion`](https://docs.rs/criterion) 0.8.2 (already a workspace dep).
- **Per-iteration latency:** [`hdrhistogram`](https://docs.rs/hdrhistogram) 7.5.4 (added as a `sentinel-hook` dev-dep in Phase 08).
- **Sample size:** criterion default (100 samples).
- **Warm-up:** criterion default (3 s warm-up; the bench function additionally calls `decide_for_sockaddr` once before the measure loop to populate the per-process cache).
- **Measurement time:** criterion default (5 s).
- **Confidence interval:** 95 % CI on the mean (criterion default).
- **Percentile method:** `hdrhistogram::Histogram::<u64>` with significant-figures = 3, populated inside `b.iter_custom(|iters| { ... })` so each iteration gets its own `Instant::now()` bracket. p99 is read via `value_at_quantile(0.99)`.

**Why criterion alone is insufficient:** criterion's stdout reports mean / median /
std-dev derived from *batched* samples — each criterion sample is one wall-clock
measurement wrapping N iterations. Per-iteration distribution is hidden in that
shape, so a sub-100µs p99 claim cannot be derived from criterion's default
output alone. The `iter_custom` + hdrhistogram pattern surfaces real
per-iteration percentiles. (See `crates/sentinel-hook/benches/cache_hit_hot_path.rs`
header for the full rationale.)

**Measurement-overhead floor:** `Instant::now()` on aarch64-apple-darwin uses
`CLOCK_UPTIME_RAW` and has ~25–50 ns of fixed call overhead. The < 100,000 ns
budget is comfortable; measurement noise is well under 1 % of the budget.

## What this does NOT measure

- Cache-miss / Resolve-IPC RTT (reported as the live-wrap context number; no fixed budget in v0.2 — Phase 08 CONTEXT D-32).
- Per-symbol bench tables (`connect` vs `nw_*` vs `getaddrinfo`).
- Comparative bench against an unsecured baseline.
- Soak / long-running / leak benches.

These are explicitly out of scope for v0.2 (Phase 08 CONTEXT, Deferred Ideas).

## Other benches in the repo

- [`crates/sentinel-hook/benches/hot_path.rs`](../crates/sentinel-hook/benches/hot_path.rs)
  is the matcher-only microbench against `sentinel_core::evaluate_rule`. It is
  preserved per Phase 08 D-37 as a regression tripwire for the rule-matching
  tier of the hot path. It is **not** load-bearing for the < 100 µs claim — see
  its header comment for details.
- [`crates/sentinel-hook/benches/cache_hit_hot_path.rs`](../crates/sentinel-hook/benches/cache_hit_hot_path.rs)
  is the load-bearing bench whose p99 lands in the table above.
- [`crates/sentinel-e2e/tests/bench_hot_path_e2e.rs`](../crates/sentinel-e2e/tests/bench_hot_path_e2e.rs)
  is the live-wrap E2E bench whose p99 lands in the live-wrap column. It is
  `#[ignore]`-gated so `cargo test --workspace` does not run it.

## How to Reproduce

On any Apple Silicon Mac with the repo cloned:

```sh
./scripts/bench-hot-path.sh
```

The script:

1. Builds the workspace in `--release`.
2. Runs `cargo bench -p sentinel-hook --bench cache_hit_hot_path` (cache-hit, binding number).
3. Runs `cargo test -p sentinel-e2e --release --test bench_hot_path_e2e -- --ignored --nocapture` (live-wrap, context number).
4. Prints a markdown table row on stdout suitable for pasting under the **Numbers** table above.

The script prints reference-machine identity (`hw.model`, `hw.memsize`,
`sw_vers`, `rustc --version`, `git rev-parse --short HEAD`, ISO UTC date) so
each row is auditable.

## Adding numbers from another SKU

1. Run `./scripts/bench-hot-path.sh` on the new machine.
2. Open a PR that appends one row to the **Numbers** table — do not overwrite
   existing rows. Phase 08 commits one reference-machine row; future SKUs land
   as PR appendices (D-35).

---

*Phase 08 / VAL-03 — see `.planning/phases/08-perf-reliability-hardening/` for the
full plan trail.*
