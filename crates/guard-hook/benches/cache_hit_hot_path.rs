//! Cache-hit microbench against `replace_libc::decide_for_sockaddr` — the
//! ACTUAL libc hot path. This is the LOAD-BEARING measurement for the D-03
//! / VAL-03 < 100µs hot-path budget (v0.7).
//!
//! The matcher-only bench at `crates/guard-hook/benches/hot_path.rs` stays
//! as a regression tripwire for `guard_core::evaluate_rule` per v0.7
//! D-37 and is NOT load-bearing for VAL-03. This file is the cross-reference
//! counterpart pointed at from `hot_path.rs`'s header.
//!
//! Why this bench is structured the way it is:
//!  * Criterion's stdout reports mean/median/std-dev — NOT p99 (RESEARCH §Pitfall 2).
//!    We use `b.iter_custom(...)` and record per-iteration `Instant::now()`-bracketed
//!    deltas into an `hdrhistogram::Histogram::<u64>::new(3)`, then `eprintln!`
//!    p50/p95/p99/p99.9/max as a separate stderr line that
//!    `scripts/bench-hot-path.sh` parses.
//!  * `ALLOWLIST` is a process-global `OnceLock` (guard-hook/src/lib.rs:50);
//!    set it ONCE before the bench loop or the bench measures a noise floor
//!    (RESEARCH §Pitfall 6). We do this via a single warm-up call to
//!    `_test_decide_for_sockaddr(entries, ...)` whose first-call side effect
//!    populates the OnceLock.
//!  * The entries Vec is NOT cloned inside the iter_custom closure
//!    (RESEARCH §Anti-Patterns: clone of a ~10-entry `Vec<AllowlistEntry>` is
//!    ~10µs and would mask the real number). After the warm-up, `_test_decide_for_sockaddr`
//!    is called with `Vec::new()` — the OnceLock.set inside the seam is silently
//!    a no-op once already set, so the empty Vec is never read. The bench
//!    measures the cache-lookup + tier-walk path against the warm-up's ALLOWLIST.
//!  * Implementation note (honest disclosure): on the bench process there is no
//!    daemon configured, so `daemon_socket_path()` returns None inside
//!    `decide_for_sockaddr`. The Resolve-IPC fallback is therefore skipped; the
//!    bench measures `sockaddr_bytes` decode + `with_cache(...)` mutex acquisition
//!    + `evaluate_policy` tier-walk against the IP — i.e. the cache-miss-against-IP
//!    branch of the libc hot path. That IS the < 100µs load-bearing surface for
//!    VAL-03 (the cache-miss Resolve-IPC path is the *context* number per D-32
//!    and lives in the live-wrap E2E bench planned downstream). Documented here
//!    so future readers don't conclude the bench is misnamed.
//!
//! See:
//!   * `crates/guard-hook/src/replace_libc.rs::decide_for_sockaddr` — function under measurement
//!   * `crates/guard-hook/src/lib.rs::_test_decide_for_sockaddr` — test seam used to drive it

use criterion::{Criterion, criterion_group, criterion_main};

// Everything below is macOS-only because it constructs `libc::sockaddr_in`
// literals whose `sin_zero` field is `[c_char; 8]`. `c_char` is `i8` on macOS
// (what we use here) but `u8` on Linux, so `[0i8; 8]` would fail to compile
// under `cargo check --workspace` on a Linux dev box. Stentorian Guard v1 is macOS-only;
// on non-macOS targets the bench group below is an empty stub so
// `criterion_main!` still produces a runnable binary.
#[cfg(target_os = "macos")]
use guard_core::{AllowlistEntry, MatchType, RuleKind, RuleTier};
#[cfg(target_os = "macos")]
use guard_hook::_test_decide_for_sockaddr;
#[cfg(target_os = "macos")]
use hdrhistogram::Histogram;
#[cfg(target_os = "macos")]
use std::hint::black_box;
#[cfg(target_os = "macos")]
use std::time::Instant;

#[cfg(target_os = "macos")]
/// Build a realistic per-run snapshot's entry mix — CuratedAllow + UserAllow,
/// Exact + Suffix + Ip match types. Mirrors what `prepare_snapshot` produces for
/// a typical npm-install run. The fixed entries match RESEARCH §Pattern 1
/// lines 358-367; the additional padding to ~10 entries makes the tier-walk
/// cost realistic without exaggerating allocation pressure.
fn realistic_entries() -> Vec<AllowlistEntry> {
    let allow = |tier: RuleTier, mt: MatchType, pattern: &str| AllowlistEntry {
        kind: RuleKind::Allow,
        tier,
        match_type: mt,
        pattern: pattern.into(),
        reason: "bench fixture".into(),
    };
    vec![
        // The four canonical entries from RESEARCH §Pattern 1.
        allow(
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "registry.npmjs.org",
        ),
        allow(RuleTier::CuratedAllow, MatchType::Suffix, ".npmjs.org"),
        allow(RuleTier::UserAllow, MatchType::Exact, "github.com"),
        allow(RuleTier::CuratedAllow, MatchType::Ip, "127.0.0.1"),
        // Padding to ~10 entries to mirror a realistic per-run snapshot mix
        // (npm install workloads typically see 50-200 — we deliberately stay
        // toward the small end so the bench number isn't dominated by
        // tier-walk length; the cache-hit fast path's load-bearing cost
        // is the lock + lookup, not the walk).
        allow(RuleTier::CuratedAllow, MatchType::Exact, "nodejs.org"),
        allow(RuleTier::CuratedAllow, MatchType::Suffix, ".jsdelivr.net"),
        allow(
            RuleTier::CuratedAllow,
            MatchType::Suffix,
            ".githubusercontent.com",
        ),
        allow(
            RuleTier::CuratedAllow,
            MatchType::Exact,
            "raw.githubusercontent.com",
        ),
        allow(RuleTier::CuratedAllow, MatchType::Exact, "pypi.org"),
        allow(
            RuleTier::CuratedAllow,
            MatchType::Suffix,
            ".pythonhosted.org",
        ),
    ]
}

#[cfg(target_os = "macos")]
/// AF_INET sockaddr literal for `104.16.16.35:443` — one of registry.npmjs.org's
/// Cloudflare IPs. Fixed value so the bench is deterministic across runs.
/// Layout matches `crates/guard-hook/tests/resolve_client_tests.rs:217-224`.
fn sockaddr_for_npmjs_443() -> (libc::sockaddr_in, libc::socklen_t) {
    let sa = libc::sockaddr_in {
        sin_len: 16,
        sin_family: libc::AF_INET as u8,
        sin_port: 443u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([104, 16, 16, 35]).to_be(),
        },
        sin_zero: [0i8; 8],
    };
    let addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    (sa, addrlen)
}

#[cfg(target_os = "macos")]
fn cache_hit_bench(c: &mut Criterion) {
    // Build the entries Vec ONCE — never cloned inside the measurement loop.
    let entries = realistic_entries();
    let (sa, addrlen) = sockaddr_for_npmjs_443();

    // Warm-up: first call sets ALLOWLIST (OnceLock; RESEARCH §Pitfall 6).
    // We discard the verdict — we only care that ALLOWLIST is now seeded so
    // subsequent calls take the fast path (no OnceLock contention).
    let _warmup = _test_decide_for_sockaddr(
        entries.clone(),
        &sa as *const _ as *const libc::sockaddr,
        addrlen,
    );

    // hdrhistogram captures per-iteration nanos from inside iter_custom.
    // sigfig=3 → 0.1% precision; ample for µs-scale measurements.
    let mut hist = Histogram::<u64>::new(3).expect("hdrhistogram new");

    c.bench_function("cache_hit/decide_for_sockaddr", |b| {
        b.iter_custom(|iters| {
            let mut total_ns: u64 = 0;
            for _ in 0..iters {
                let t0 = Instant::now();
                // Pass an empty Vec — `_test_decide_for_sockaddr` does
                // `let _ = ALLOWLIST.set(entries)` which silently no-ops once
                // ALLOWLIST is set, so the empty Vec is never read. The bench
                // measures `decide_for_sockaddr` against the warm-up's
                // ALLOWLIST.
                let _v = _test_decide_for_sockaddr(
                    Vec::new(),
                    black_box(&sa as *const _ as *const libc::sockaddr),
                    black_box(addrlen),
                );
                let dt = t0.elapsed();
                let ns = dt.as_nanos() as u64;
                hist.record(ns).ok();
                total_ns = total_ns.saturating_add(ns);
            }
            std::time::Duration::from_nanos(total_ns)
        })
    });

    // Print percentile line — `scripts/bench-hot-path.sh`
    // greps for `p99=` from this. Intentionally NO assertion against a
    // hard p99 threshold (D-33: no CI gate).
    eprintln!(
        "cache_hit/decide_for_sockaddr  p50={}ns  p95={}ns  p99={}ns  p99.9={}ns  max={}ns",
        hist.value_at_quantile(0.50),
        hist.value_at_quantile(0.95),
        hist.value_at_quantile(0.99),
        hist.value_at_quantile(0.999),
        hist.max()
    );
}

// Non-macOS stub: keeps `criterion_main!` linkable on Linux/Windows so
// `cargo check --workspace` doesn't fail with "no `main` symbol". The bench
// group is intentionally empty — Stentorian Guard is macOS-only by charter.
#[cfg(not(target_os = "macos"))]
fn cache_hit_bench(_c: &mut Criterion) {}

criterion_group!(benches, cache_hit_bench);
criterion_main!(benches);
