//! Trusted `.sentinel.toml` rule-rendering helper.
//!
//! Phase 07 plan 04 (D-13): the v0.1 `sentinel trust-policy <path>`
//! subcommand is deleted. The first-trust prompt now lives inside
//! `run_orchestrator::run` (D-24/D-25) and is fired automatically when a
//! wrapped command encounters an untrusted `.sentinel.toml` walked from cwd.
//! `display_rules` survives as the canonical renderer used both by the new
//! prompt locus and by `status rules --project` rendering when those land.

use sentinel_core::policy_file::SentinelToml;

pub fn display_rules(toml: &SentinelToml) {
    println!("{:<8} {:<8} {:<50} reason", "kind", "match", "pattern");
    let separator = "-".repeat(100);
    println!("{separator}");
    for r in &toml.rules {
        let kind = format!("{:?}", r.kind).to_lowercase();
        let mt = format!("{:?}", r.match_type).to_lowercase();
        println!(
            "{kind:<8} {mt:<8} {:<50} {}",
            r.pattern, r.reason,
        );
    }
}
