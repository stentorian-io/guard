#!/usr/bin/env bash
# scripts/bench-hot-path.sh — one-command bench runner for hot-path benchmarks.
#
# Reproduces hot-path benchmark numbers on any M-series Apple Silicon Mac.
#
# Usage:
#   ./scripts/bench-hot-path.sh
#
# Output:
#   * Progress markers on stderr.
#   * A markdown table summary on stdout.
#
# Sources:
#   * CONTEXT D-33 (one-command local runner; no CI gate)
#   * CONTEXT D-36
#   * RESEARCH Code Examples A
#   * RESEARCH Pitfall 7 (--release required for live-wrap E2E bench)

set -euo pipefail

# ---------------------------------------------------------------------------
# --dry-run mode: validate percentile-extraction greps against synthetic
# samples WITHOUT running cargo bench / cargo test. Use this on any dev
# machine to confirm the runner is wired correctly before committing time
# on the reference Apple Silicon machine. Prints `dry-run: ok` on success;
# exits non-zero if any grep regression is detected.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--dry-run" ]]; then
    # Synthetic samples copied from the actual bench output shapes (verified
    # 2026-05-09 — see 08-VERIFICATION.md behavioral spot-checks).
    SAMPLE_CACHE_HIT='cache_hit/decide_for_sockaddr p50=541ns p95=541ns p99=541ns p99.9=541ns max=541ns'
    SAMPLE_LIVE_WRAP='LIVE_WRAP_NS p50=12345 p95=23456 p99=34567 p999=45678 max=56789'

    # Matches the production extraction below: both columns capture the bare
    # numeric value (no `ns` suffix) so the "unknown" fallback renders cleanly.
    DRY_CACHE_HIT_P99="$(printf '%s\n' "$SAMPLE_CACHE_HIT" | grep -oE 'p99=[0-9]+' | head -1 | sed 's/^p99=//')"
    DRY_LIVE_WRAP_P99="$(printf '%s\n' "$SAMPLE_LIVE_WRAP" | grep -oE 'p99=[0-9]+' | head -1 | sed 's/^p99=//')"

    if [[ -z "$DRY_CACHE_HIT_P99" ]]; then
        echo "dry-run FAIL: cache-hit grep ('p99=[0-9]+') did not match the synthetic sample." >&2
        echo "  sample: $SAMPLE_CACHE_HIT" >&2
        echo "  fix: update the grep regex in this script OR the eprintln! in crates/sentinel-hook/benches/cache_hit_hot_path.rs so they agree." >&2
        exit 1
    fi
    if [[ -z "$DRY_LIVE_WRAP_P99" ]]; then
        echo "dry-run FAIL: live-wrap grep ('p99=[0-9]+') did not match the synthetic sample." >&2
        echo "  sample: $SAMPLE_LIVE_WRAP" >&2
        echo "  fix: update the grep regex in this script OR the console.log in crates/sentinel-e2e/tests/bench_hot_path_e2e.rs so they agree." >&2
        exit 1
    fi

    echo "dry-run: ok"
    echo "  cache-hit p99 extracted from synthetic sample: $DRY_CACHE_HIT_P99"
    echo "  live-wrap p99 extracted from synthetic sample: $DRY_LIVE_WRAP_P99"
    echo "  the runner is wired correctly; capture the real numbers via:"
    echo "    ./scripts/bench-hot-path.sh    (no flags) on the reference Apple Silicon machine"
    exit 0
fi

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
# Per-run scratch dir under $TMPDIR (per-user `/var/folders/...` on macOS,
# mode 0700) instead of fixed paths under /tmp. /tmp is /private/tmp mode
# 1777 on macOS — a pre-placed symlink at /tmp/bench-cache-hit.out would
# let `tee` clobber a target chosen by another local user. mktemp -d is
# symlink-pivot-safe by construction; the trap cleans up on every exit
# (including SIGINT / SIGTERM / SIGHUP) so we don't litter $TMPDIR.
# ---------------------------------------------------------------------------
SCRATCH="$(mktemp -d -t bench-hot-path)"
trap 'rm -rf "$SCRATCH"' EXIT INT TERM HUP

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
    | tee "$SCRATCH/bench-cache-hit.out"

# ---------------------------------------------------------------------------
# Live-wrap E2E bench — the CONTEXT number for VAL-03 (no fixed budget).
# Requires --release explicitly because cargo test default is dev profile.
# ---------------------------------------------------------------------------
echo "## bench-hot-path: live-wrap (context number) ..." >&2
cargo test -p sentinel-e2e --release --test bench_hot_path_e2e -- \
    --ignored --nocapture 2>&1 \
    | tee "$SCRATCH/bench-live-wrap.out"

# ---------------------------------------------------------------------------
# Extract percentile values from each bench's output. Both extractions
# capture the bare numeric value (no `ns` suffix) so the fallback to
# "unknown" renders cleanly — previously cache-hit captured `12345ns`
# while live-wrap captured `12345`, and on the unknown-fallback path the
# live-wrap column rendered as `unknownns`. Adding the suffix uniformly
# in fmt_ns() below keeps the two columns parallel on both happy and
# fallback paths.
# Defense-in-depth || echo unknown: bash's `set -e` does NOT propagate
# errexit into command substitutions without `inherit_errexit`, so a
# failing pipeline yields an empty string and the `:=` fallback fires —
# but versions and shopt-state vary, so the explicit `|| echo unknown`
# is the belt-and-suspenders.
# ---------------------------------------------------------------------------
CACHE_HIT_P99="$(grep -oE 'p99=[0-9]+' "$SCRATCH/bench-cache-hit.out" | head -1 | sed 's/^p99=//' || echo unknown)"
LIVE_WRAP_P99="$(grep -oE 'p99=[0-9]+' "$SCRATCH/bench-live-wrap.out" | head -1 | sed 's/^p99=//' || echo unknown)"

# Fall back to "unknown" if either grep returned empty.
: "${CACHE_HIT_P99:=unknown}"
: "${LIVE_WRAP_P99:=unknown}"

# Render with conditional `ns` suffix so the "unknown" fallback doesn't
# end up as "unknownns". Used in the markdown row below.
fmt_ns() { [ "$1" = "unknown" ] && echo "$1" || echo "${1}ns"; }
CACHE_HIT_P99_FMT="$(fmt_ns "$CACHE_HIT_P99")"
LIVE_WRAP_P99_FMT="$(fmt_ns "$LIVE_WRAP_P99")"

# ---------------------------------------------------------------------------
# Markdown summary table.
# ---------------------------------------------------------------------------
cat <<EOF

## Bench Summary

Benchmark results:

| machine | RAM | macOS | rustc | git SHA | date (UTC) | cache-hit p99 | live-wrap p99 |
|---------|-----|-------|-------|---------|------------|----------------|----------------|
| ${MAC_MODEL} | ${MEM_GB} GB | ${MACOS_VER} | ${RUSTC_VER} | ${GIT_SHA} | ${ISO_DATE} | ${CACHE_HIT_P99_FMT} | ${LIVE_WRAP_P99_FMT} |

Methodology: criterion 0.8.2, hdrhistogram 7.5.4. Sample size and warm-up are
criterion defaults (100 samples, 3s warm-up, 5s measurement_time, 95% CI on the
mean). p99 is computed via hdrhistogram::value_at_quantile(0.99) on
per-iteration nanoseconds captured inside b.iter_custom(...).

Reproduce: ./scripts/bench-hot-path.sh on any Apple Silicon Mac with the
workspace built.
EOF
