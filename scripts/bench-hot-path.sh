#!/usr/bin/env bash
# scripts/bench-hot-path.sh — Phase 08 / VAL-03 one-command bench runner.
#
# Reproduces docs/BENCH.md numbers on any M-series Apple Silicon Mac.
#
# Usage:
#   ./scripts/bench-hot-path.sh
#
# Output:
#   * Progress markers on stderr.
#   * A markdown table summary on stdout suitable for pasting into docs/BENCH.md.
#
# Sources:
#   * CONTEXT D-33 (one-command local runner; no CI gate)
#   * CONTEXT D-36 (docs/BENCH.md location)
#   * RESEARCH Code Examples A
#   * RESEARCH Pitfall 7 (--release required for live-wrap E2E bench)

set -euo pipefail

# ---------------------------------------------------------------------------
# Reference-machine identity block (printed in the markdown header).
# ---------------------------------------------------------------------------
GIT_SHA="$(git rev-parse --short HEAD)"
ISO_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
MAC_MODEL="$(sysctl -n hw.model 2>/dev/null || echo unknown)"
MEM_BYTES="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
MEM_GB="$(( MEM_BYTES / 1073741824 ))"
MACOS_VER="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
RUSTC_VER="$(rustc --version 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# Build first so the live-wrap bench's --release invocation is fast.
# ---------------------------------------------------------------------------
echo "## bench-hot-path: building workspace --release ..." >&2
cargo build --workspace --release

# ---------------------------------------------------------------------------
# In-process cache-hit bench — the BINDING number for VAL-03.
# (cargo bench defaults to the bench profile, which is release-like — RESEARCH Pitfall 7.)
# ---------------------------------------------------------------------------
echo "## bench-hot-path: cache-hit (binding number) ..." >&2
cargo bench -p sentinel-hook --bench cache_hit_hot_path 2>&1 \
    | tee /tmp/bench-cache-hit.out

# ---------------------------------------------------------------------------
# Live-wrap E2E bench — the CONTEXT number for VAL-03 (no fixed budget).
# Requires --release explicitly because cargo test default is dev profile.
# ---------------------------------------------------------------------------
echo "## bench-hot-path: live-wrap (context number) ..." >&2
cargo test -p sentinel-e2e --release --test bench_hot_path_e2e -- \
    --ignored --nocapture 2>&1 \
    | tee /tmp/bench-live-wrap.out

# ---------------------------------------------------------------------------
# Extract percentile values from each bench's output.
# ---------------------------------------------------------------------------
CACHE_HIT_P99="$(grep -oE 'p99=[0-9]+ns' /tmp/bench-cache-hit.out | head -1 | sed 's/^p99=//')"
LIVE_WRAP_P99="$(grep -oE 'p99=[0-9]+' /tmp/bench-live-wrap.out | head -1 | sed 's/^p99=//')"

# Fall back to "unknown" if either grep returned empty.
: "${CACHE_HIT_P99:=unknown}"
: "${LIVE_WRAP_P99:=unknown}"

# ---------------------------------------------------------------------------
# Markdown summary table — paste into docs/BENCH.md.
# ---------------------------------------------------------------------------
cat <<EOF

## Bench Summary

Paste the row below into docs/BENCH.md under the numbers table.

| machine | RAM | macOS | rustc | git SHA | date (UTC) | cache-hit p99 | live-wrap p99 |
|---------|-----|-------|-------|---------|------------|----------------|----------------|
| ${MAC_MODEL} | ${MEM_GB} GB | ${MACOS_VER} | ${RUSTC_VER} | ${GIT_SHA} | ${ISO_DATE} | ${CACHE_HIT_P99} | ${LIVE_WRAP_P99}ns |

Methodology: criterion 0.8.2, hdrhistogram 7.5.4. Sample size and warm-up are
criterion defaults (100 samples, 3s warm-up, 5s measurement_time, 95% CI on the
mean). p99 is computed via hdrhistogram::value_at_quantile(0.99) on
per-iteration nanoseconds captured inside b.iter_custom(...).

Reproduce: ./scripts/bench-hot-path.sh on any Apple Silicon Mac with the
workspace built.
EOF
