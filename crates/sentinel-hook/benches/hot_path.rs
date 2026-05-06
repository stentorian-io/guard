//! ENF-06 microbench — Phase 1 SCOPE IS MATCHER-ONLY (ISS-06).
//!
//! This bench exercises `sentinel_core::evaluate_rule` against a 4-entry
//! Phase 1-equivalent allowlist (Phase 2 V2 struct shape). It does NOT
//! exercise the cache lookup path, the sockaddr decoding path, or the Mutex
//! protecting the per-process cache. Those layers are part of the FULL hot
//! path and are NOT verified by this microbench. The formal under-load
//! benchmark on real hardware lands in Phase 5 (VAL-03) and is the binding
//! number for the < 100µs project constraint; this bench is a regression
//! detector for the matcher component only.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_core::{evaluate_rule, AllowlistEntry, MatchType, RuleKind, RuleTier, Verdict};

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

fn bench_matcher(c: &mut Criterion) {
    let entries: Vec<AllowlistEntry> = vec![
        entry(RuleKind::Allow, MatchType::Exact, "registry.npmjs.org"),
        entry(RuleKind::Allow, MatchType::Suffix, ".example.com"),
        entry(RuleKind::Allow, MatchType::Ip, "127.0.0.1"),
        entry(RuleKind::Allow, MatchType::Exact, "localhost"),
    ];
    c.bench_function("match exact hit npmjs", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"registry.npmjs.org")))
    });
    c.bench_function("match suffix hit example.com", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"foo.bar.example.com")))
    });
    c.bench_function("match miss evil.example.org", |b| {
        b.iter(|| walk(black_box(&entries), black_box(b"evil.example.org")))
    });
}

criterion_group!(benches, bench_matcher);
criterion_main!(benches);
