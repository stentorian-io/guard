//! ENF-06 microbench — Phase 1 SCOPE IS MATCHER-ONLY (ISS-06).
//!
//! This bench exercises `sentinel_core::match_hostname` against a 4-entry
//! Phase 1 allowlist. It does NOT exercise the cache lookup path, the
//! sockaddr decoding path, or the Mutex protecting the per-process cache.
//! Those layers are part of the FULL hot path and are NOT verified by this
//! microbench. The formal under-load benchmark on real hardware lands in
//! Phase 5 (VAL-03) and is the binding number for the < 100µs project
//! constraint; this Phase 1 bench is a regression detector for the matcher
//! component only.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_core::{match_hostname, AllowlistEntry};

fn bench_matcher(c: &mut Criterion) {
    let entries: Vec<AllowlistEntry> = vec![
        AllowlistEntry::Exact("registry.npmjs.org".into()),
        AllowlistEntry::Suffix(".example.com".into()),
        AllowlistEntry::Ip("127.0.0.1".into()),
        AllowlistEntry::Exact("localhost".into()),
    ];
    c.bench_function("match exact hit npmjs", |b| {
        b.iter(|| match_hostname(black_box(&entries), black_box(b"registry.npmjs.org")))
    });
    c.bench_function("match suffix hit example.com", |b| {
        b.iter(|| match_hostname(black_box(&entries), black_box(b"foo.bar.example.com")))
    });
    c.bench_function("match miss evil.example.org", |b| {
        b.iter(|| match_hostname(black_box(&entries), black_box(b"evil.example.org")))
    });
}

criterion_group!(benches, bench_matcher);
criterion_main!(benches);
