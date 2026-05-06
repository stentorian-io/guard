//! Misleading microbench — MATCHER-ONLY, NOT load-bearing for the D-03
//! < 100µs hot-path budget.
//!
//! WARNING-01 (Phase 2 review): the previous header for this file was
//! "ENF-06 microbench" which a casual reader could interpret as a measurement
//! of the full < 100µs hot path. It is NOT. This bench exercises
//! `sentinel_core::evaluate_rule` (single-entry matcher) inside a hand-rolled
//! `walk()` helper — neither of which is on the actual hot path. The real
//! libc hook hot path goes through `replace_libc.rs::decide_for_sockaddr` →
//! `with_cache(...)` (process-global Mutex<Cache>) →
//! `sentinel_core::policy::evaluate_policy` (tier-walk).
//!
//! Naming the bench more honestly + flagging the criterion group as
//! `misleading_micro_bench` keeps it useful as a matcher regression
//! detector while preventing future readers from concluding that the
//! D-03 budget has been verified by criterion. The formal under-load
//! benchmark on real hardware lands in Phase 5 (VAL-03) and is the
//! binding number for the < 100µs constraint.

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
