//! MATCHER-ONLY microbench against `sentinel_core::evaluate_rule`.
//!
//! NOT load-bearing for the D-03 / VAL-03 < 100µs hot-path budget — this file
//! exercises only the rule-matching tier of the hot path (CuratedAllow Exact /
//! Suffix / Ip walks via `evaluate_rule`). It does NOT exercise:
//!  * `with_cache(...)` mutex acquisition (the actual per-call locking cost),
//!  * `decide_for_sockaddr` sockaddr-decode + cache-lookup,
//!  * the full tier-walking `evaluate_policy` traversal.
//!
//! The LOAD-BEARING measurement for VAL-03 lives at
//! `crates/sentinel-hook/benches/cache_hit_hot_path.rs` and uses
//! criterion's `iter_custom` + an `hdrhistogram` to surface a real p99 line.
//!
//! Both benches run together via `cargo bench -p sentinel-hook`. This file is
//! preserved per Phase 08 D-37 as a regression tripwire for `evaluate_rule`.

use criterion::{criterion_group, criterion_main, Criterion};
use sentinel_core::{evaluate_rule, AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict};
use std::hint::black_box;

fn entry(kind: RuleKind, mt: MatchType, pattern: &str) -> AllowlistEntry {
    AllowlistEntry {
        kind,
        tier: RuleTier::CuratedAllow,
        match_type: mt,
        pattern: pattern.into(),
        reason: "bench".into(),
    }
}

#[inline]
fn walk(entries: &[AllowlistEntry], host: &[u8]) -> Verdict {
    for e in entries {
        if let Some(v) = evaluate_rule(e, host) {
            return v;
        }
    }
    Verdict::Deny
}

fn misleading_micro_bench(c: &mut Criterion) {
    // Matcher-only; NOT load-bearing for the D-03 < 100µs hot-path budget.
    // Prefix the bench-function names with "misleading-microbench" so a
    // reader skimming criterion output cannot mistake these numbers for a
    // hot-path measurement.
    let entries: Vec<AllowlistEntry> = vec![
        entry(RuleKind::Allow, MatchType::Exact, "registry.npmjs.org"),
        entry(RuleKind::Allow, MatchType::Suffix, ".example.com"),
        entry(RuleKind::Allow, MatchType::Ip, "127.0.0.1"),
        entry(RuleKind::Allow, MatchType::Exact, "localhost"),
    ];
    c.bench_function("misleading-microbench/match exact hit npmjs", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"registry.npmjs.org")))
    });
    c.bench_function("misleading-microbench/match suffix hit example.com", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"foo.bar.example.com")))
    });
    c.bench_function("misleading-microbench/match miss evil.example.org", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"evil.example.org")))
    });
}

criterion_group!(benches, misleading_micro_bench);
criterion_main!(benches);
