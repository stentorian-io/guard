//! Phase 4 plan 04-02 — gix shallow-clone + fetch loop with deadline +
//! panic isolation + parse-on-fetch + metadata recording.
//!
//! Per 04-SPIKE-RESULTS.md A1: the gix call chains for first-clone and
//! incremental-fetch are copied verbatim from spike_gix.rs's
//! `// SPIKE-API-VERIFIED:` comments. They compiled against gix 0.83 with
//! the workspace's `worktree-mutation` + `sha1` features.
//!
//! Per 04-SPIKE-RESULTS.md A2: `panic = "unwind"` is REJECTED by cargo
//! (workspace stays at `panic = "abort"`). `std::panic::catch_unwind` is
//! therefore a NO-OP at runtime in the production daemon binary — gix
//! panics SIGABRT the daemon, and Phase 3's launchd LaunchAgent KeepAlive
//! restarts it. The `catch_unwind` wrapper IS retained here so:
//!   1. the code is compile-time correct AND useful under `cargo test`
//!      (test runner forces `panic = unwind` regardless of profile);
//!   2. a future cargo release that allows per-package panic = unwind can
//!      flip the runtime semantics without touching this code.
//! See 04-SPIKE-RESULTS.md A2 for the launchd KeepAlive recovery path.
//!
//! Per RESEARCH.md Pitfall 1: the 60s ceiling fails first-time clones
//! (GHSA shallow clone is 78s wall-clock on Apple Silicon). First-run gets
//! 120s; incremental gets 60s. Detected via `local.join(".git").exists()`.
//!
//! Per RESEARCH.md Pitfall 6: gix incremental-fetch reuses
//! `.git/config`'s upstream URL. We verify `remote.origin.url == url` on
//! every open-existing path; mismatch triggers a wipe + fresh clone (also
//! handles `SENTINEL_FEED_URL_OVERRIDE_*` flips for fixture tests).

use std::num::NonZeroU32;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sentinel_ipc::FeedWarning;

use crate::feed::parser::{parse_osv_record, FeedParseError, ParsedRecord};
use crate::feed::store::{FeedIocRow, FeedMetadataRow, FeedStore, FeedStoreError, unix_ms_now};

pub const FETCH_DEADLINE_FIRST_RUN: Duration = Duration::from_secs(120);
pub const FETCH_DEADLINE_INCREMENTAL: Duration = Duration::from_secs(60);

/// Production feed sources (D-80). Override per-feed for hermetic e2e tests
/// via `SENTINEL_FEED_URL_OVERRIDE_OSV` / `SENTINEL_FEED_URL_OVERRIDE_GHSA`
/// — see `url_override_for`.
pub const FEEDS: &[(&str, &str)] = &[
    ("OSV", "https://github.com/ossf/malicious-packages.git"),
    ("GHSA", "https://github.com/github/advisory-database.git"),
];

/// Threshold above which a fetch is treated as too-many-malformed; if the
/// failure rate is at-or-above this AND there is at least one parse error,
/// the fetcher SKIPS the store-write step (D-87 last-good-cache path).
pub const PARSE_FAILURE_RATIO_THRESHOLD: f64 = 0.5;

/// WR-09 fix: cap on per-feed `feed_warnings` returned in the
/// PrepareSnapshot V4 reply. The IPC frame is bounded by
/// `sentinel_ipc::frame::MAX_FRAME_BYTES` (64 KiB); a malicious or
/// corrupted feed snapshot with thousands of malformed records used to
/// inflate `Vec<FeedWarning>` past the frame budget, causing
/// `write_frame` to fail and the entire PrepareSnapshot RPC to error
/// out — even when the underlying last-good-cache path was intact.
/// 8 warnings × ~150 bytes = ~1.2 KiB CBOR per feed (2 feeds → ~2.4
/// KiB), well under the frame budget. The full warnings still reach
/// `tracing::warn!` (target = "sentinel.feed.fetch") for forensic
/// analysis; the IPC reply is just inline UX, where 8 + a "truncated"
/// counter line is more than enough.
pub const MAX_FEED_WARNINGS_PER_FEED: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum FeedFetchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("git ({feed}): {message}")]
    Git { feed: String, message: String },
    #[error("timeout ({feed}): exceeded {seconds}s ceiling")]
    Timeout { feed: String, seconds: u64 },
    #[error("panic ({feed}): {message}")]
    Panic { feed: String, message: String },
    #[error("store: {0}")]
    Store(#[from] FeedStoreError),
}

#[derive(Debug, Clone)]
pub struct FetchOutcome {
    pub feed: String,            // "OSV" or "GHSA"
    pub commit_sha: String,
    pub records_parsed: usize,
    pub records_failed: usize,
    pub host_iocs_extracted: usize,
    pub schema_version_observed: Option<String>,
    pub warnings: Vec<FeedWarning>,
}

/// Per-feed env-var override (D-94 hermetic e2e fixture path). Returns
/// `Some(url)` when set, `None` otherwise — the fetcher then falls back to
/// the production URL in `FEEDS`.
pub fn url_override_for(feed: &str) -> Option<String> {
    let var = match feed {
        "OSV" => "SENTINEL_FEED_URL_OVERRIDE_OSV",
        "GHSA" => "SENTINEL_FEED_URL_OVERRIDE_GHSA",
        _ => return None,
    };
    std::env::var(var).ok()
}

/// Fetch one feed: shallow-clone (first run) or incremental fetch (subsequent),
/// then walk the worktree, parse each `*.json`, write rows + metadata.
///
/// `local` is the per-feed cache directory (`$state_dir/feeds/<feed>/`);
/// the gix repo lives directly there.
pub fn fetch_one_feed(
    feed_name: &str,
    url: &str,
    local: &Path,
    deadline: Instant,
    deadline_seconds: u64,
    feed_store: &FeedStore,
) -> Result<FetchOutcome, FeedFetchError> {
    // Watchdog: a sleeper thread flips `interrupt` to true at deadline.
    // gix observes the AtomicBool and aborts in-flight network/checkout work.
    let interrupt = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = spawn_deadline_watchdog(Arc::clone(&interrupt), Arc::clone(&done), deadline);

    // Wrap the whole fetch+parse body in catch_unwind. Per 04-SPIKE-RESULTS.md
    // A2 this is a no-op under panic=abort (production daemon profile) but
    // remains compile-time correct AND useful under cargo test (which forces
    // unwind via test-runner profile).
    let feed_name_owned = feed_name.to_string();
    let result = catch_unwind(AssertUnwindSafe(|| {
        fetch_one_feed_impl(
            feed_name,
            url,
            local,
            &interrupt,
            deadline,
            deadline_seconds,
            feed_store,
        )
    }));

    // Signal the watchdog to exit; join is best-effort (its sleep wakes
    // periodically via the `done` flag).
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    match result {
        Ok(r) => r,
        Err(panic_payload) => {
            let message = panic_payload_to_string(panic_payload);
            tracing::error!(
                target = "sentinel.feed.fetch",
                event = "feed_error",
                feed = feed_name_owned,
                kind = "panic",
                message = %message,
                "gix panicked during fetch — feed marked panic outcome"
            );
            // Best-effort metadata write so the daemon's StatusReply can
            // surface the panic. Ignore secondary errors.
            let _ = feed_store.update_metadata(&FeedMetadataRow {
                feed: feed_name_owned.clone(),
                last_pull_ms: unix_ms_now(),
                last_pull_outcome: "panic".to_string(),
                last_commit_sha: None,
                schema_version_observed: None,
                error_message: Some(message.clone()),
                record_count: 0,
            });
            Err(FeedFetchError::Panic {
                feed: feed_name_owned,
                message,
            })
        }
    }
}

fn fetch_one_feed_impl(
    feed_name: &str,
    url: &str,
    local: &Path,
    interrupt: &AtomicBool,
    deadline: Instant,
    deadline_seconds: u64,
    feed_store: &FeedStore,
) -> Result<FetchOutcome, FeedFetchError> {
    // TI-08 observability: emit a structured tracing event at the START of
    // every actual outbound fetch attempt. Plan 04-04 task 4's
    // feed_no_per_query.rs counts `op="fetch_start"` substrings — a stable
    // probe for "did the daemon make an outbound fetch?" without being
    // confused by other tracing events on the same target.
    tracing::info!(
        target = "sentinel.feed.fetch",
        op = "fetch_start",
        feed = feed_name,
        url = url,
        "fetch starting",
    );

    // Ensure the parent directory exists (per-feed cache lives at
    // $state_dir/feeds/<feed>/, the parent feeds_dir is created by
    // concurrency::fetch_feeds_blocking before this entry point).
    if let Some(parent) = local.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let _is_first_run = !local.join(".git").exists();
    let repo = if local.join(".git").exists() {
        // Open existing — verify origin URL (Pitfall 6 mitigation: e.g.
        // `remote.origin.url` may be stale if SENTINEL_FEED_URL_OVERRIDE_*
        // changed between runs).
        //
        // WR-02 fix: prior comparison was `u.to_bstring().to_string() == url`,
        // which is too strict — `gix::Url::to_bstring()` produces a canonical
        // serialized form that can differ from a user-supplied input string in
        // trailing `.git`, trailing slash, lowercased host, default ports,
        // IPv6 bracket normalization, and file:// path canonicalization. A
        // production switch between
        //   https://github.com/ossf/malicious-packages
        // and
        //   https://github.com/ossf/malicious-packages.git
        // would burn ~78s of fresh-clone wall time even though the user's
        // intent and the stored origin agree. Normalize BOTH sides through
        // `gix::url::parse` and compare the resulting `gix::Url` values.
        let origin_matches = match gix::open(local) {
            Ok(repo) => match repo.find_remote("origin") {
                Ok(remote) => remote
                    .url(gix::remote::Direction::Fetch)
                    .map(|u| urls_match(u, url))
                    .unwrap_or(false),
                Err(_) => false,
            },
            Err(_) => false,
        };
        if !origin_matches {
            // Wipe and re-clone.
            tracing::info!(
                target = "sentinel.feed.fetch",
                feed = feed_name,
                "origin.url mismatch (Pitfall 6) — wiping cache and re-cloning"
            );
            // Best-effort: remove the cache. If removal fails, fresh-clone
            // will fail too and surface a clear error.
            let _ = std::fs::remove_dir_all(local);
            clone_fresh(feed_name, url, local, interrupt, deadline, deadline_seconds)?
        } else {
            // SPIKE-API-VERIFIED: gix 0.83 incremental-fetch call chain.
            //   1. gix::open(local) -> Repository
            //   2. repo.find_remote("origin") -> Remote
            //   3. remote.connect(remote::Direction::Fetch) -> Connection
            //   4. connection.prepare_fetch(&mut Discard, ref_map::Options::default()) -> Prepare
            //   5. prepared.with_shallow(Shallow::DepthAtRemote(1)).receive(&mut Discard, &AtomicBool)
            let repo = gix::open(local).map_err(|e| FeedFetchError::Git {
                feed: feed_name.to_string(),
                message: format!("open: {e}"),
            })?;
            let remote = repo.find_remote("origin").map_err(|e| FeedFetchError::Git {
                feed: feed_name.to_string(),
                message: format!("find_remote: {e}"),
            })?;
            let connection = remote
                .connect(gix::remote::Direction::Fetch)
                .map_err(|e| FeedFetchError::Git {
                    feed: feed_name.to_string(),
                    message: format!("connect: {e}"),
                })?;
            let mut progress = gix::progress::Discard;
            let prepared = connection
                .prepare_fetch(&mut progress, gix::remote::ref_map::Options::default())
                .map_err(|e| FeedFetchError::Git {
                    feed: feed_name.to_string(),
                    message: format!("prepare_fetch: {e}"),
                })?;
            check_deadline(feed_name, deadline, deadline_seconds, interrupt)?;
            let _outcome = prepared
                .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
                    NonZeroU32::new(1).expect("nonzero"),
                ))
                .receive(&mut progress, interrupt)
                .map_err(|e| classify_git_err(feed_name, deadline, deadline_seconds, interrupt, e))?;
            repo
        }
    } else {
        clone_fresh(feed_name, url, local, interrupt, deadline, deadline_seconds)?
    };

    let commit_sha = head_sha(&repo).map_err(|e| FeedFetchError::Git {
        feed: feed_name.to_string(),
        message: format!("head: {e}"),
    })?;

    // Walk worktree, parse each *.json, build rows.
    let workdir = repo.workdir().ok_or_else(|| FeedFetchError::Git {
        feed: feed_name.to_string(),
        message: "bare repo has no worktree".into(),
    })?;

    let mut records_parsed = 0usize;
    let mut records_failed = 0usize;
    let mut records_schema_unknown = 0usize;
    let mut warnings: Vec<FeedWarning> = Vec::new();
    let mut schema_version_observed: Option<String> = None;
    let mut total_records = 0usize;

    let mut rows: Vec<FeedIocRow> = Vec::new();
    let mut host_iocs_count: usize = 0;

    for entry in walkdir::WalkDir::new(workdir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        // Deadline check between files — long parse loops should still abort.
        if Instant::now() >= deadline || interrupt.load(Ordering::SeqCst) {
            return Err(FeedFetchError::Timeout {
                feed: feed_name.to_string(),
                seconds: deadline_seconds,
            });
        }

        total_records += 1;
        let bytes = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(_) => {
                records_failed += 1;
                continue;
            }
        };
        match parse_osv_record(&bytes, feed_name) {
            Ok(parsed) => {
                schema_version_observed
                    .get_or_insert_with(|| parsed.schema_version_observed.clone());
                let added = build_rows_from_parsed(feed_name, &parsed, &mut rows);
                host_iocs_count += parsed.host_iocs.len();
                // WR-04 fix: count `records_parsed` by the rows actually
                // produced. The previous `.max(1)` floor over-counted
                // structurally empty records (e.g., a withdrawn advisory
                // with no affected blocks AND no host_iocs), inflating
                // `feed_metadata.record_count` AND breaking the
                // `all_failures_schema_unknown` reclassification gate
                // below — a single empty-but-valid record bumped
                // records_parsed to 1 and suppressed the schema_unknown
                // outcome.
                records_parsed += added;
            }
            Err(e) => {
                records_failed += 1;
                if matches!(e, FeedParseError::SchemaUnknown { .. }) {
                    records_schema_unknown += 1;
                    // Capture the observed schema version so feed_metadata's
                    // schema_version_observed field reflects what was rejected
                    // (helps `sentinel status --verbose` debugging).
                    if schema_version_observed.is_none() {
                        if let FeedParseError::SchemaUnknown { observed: Some(v) } = &e {
                            schema_version_observed = Some(v.clone());
                        }
                    }
                }
                handle_parse_error(feed_name, &e, &mut warnings);
            }
        }
    }

    // D-87: if more than half of records failed parse, keep last-good cache
    // (skip delete+upsert) but still update metadata so StatusReply surfaces
    // the failure mode. Strict `>` so that an even 50/50 split still writes
    // the good rows.
    let too_many_failed = total_records > 0
        && records_failed > 0
        && (records_failed as f64 / total_records as f64) > PARSE_FAILURE_RATIO_THRESHOLD;

    // TI-06 surfacing: when EVERY parse failure is a SchemaUnknown rejection
    // (and there are no successful records — i.e. the feed has zero rows we
    // could accept), record `last_pull_outcome = "schema_unknown"` rather
    // than the generic "parse_error". This is the load-bearing signal for
    // `sentinel status --json` to surface "feed schema-version newer than
    // sentinel knows about — please upgrade" rather than the generic
    // "parse_error" diagnostic.
    let all_failures_schema_unknown =
        records_failed > 0 && records_schema_unknown == records_failed && records_parsed == 0;
    let outcome_kind = if all_failures_schema_unknown {
        "schema_unknown"
    } else if too_many_failed {
        "parse_error"
    } else if records_failed > 0 {
        // Some failed but under threshold — still mark parse_error so the
        // schema_unknown / oversized signal reaches Status. The good rows
        // are written.
        "parse_error"
    } else {
        "ok"
    };

    if !too_many_failed && !rows.is_empty() {
        // CR-01 fix: atomic delete+insert in a single transaction so a
        // concurrent reader on a separate WAL connection cannot observe an
        // empty feed_iocs window between two writes. The previous two-step
        // delete_feed + upsert_iocs sequence let a parallel `sentinel wrap`
        // land an empty FeedDeny set in its snapshot during the refresh
        // window — directly threatens project core value (compromised
        // package can slip past during refresh).
        feed_store.replace_feed_iocs(feed_name, &rows)?;
    } else if too_many_failed {
        tracing::warn!(
            target = "sentinel.feed.fetch",
            event = "feed_error",
            feed = feed_name,
            kind = "parse_error",
            records_parsed,
            records_failed,
            "skipping store write — too many parse failures (last-good cache retained)"
        );
    }

    let final_outcome = if all_failures_schema_unknown {
        // Schema-unknown signals "feed format newer than sentinel knows" —
        // preserve that signal even when last-good-cache is retained.
        "schema_unknown".to_string()
    } else if too_many_failed {
        // Override to ensure metadata reflects the last-good-cache decision.
        "parse_error".to_string()
    } else {
        outcome_kind.to_string()
    };

    feed_store.update_metadata(&FeedMetadataRow {
        feed: feed_name.to_string(),
        last_pull_ms: unix_ms_now(),
        last_pull_outcome: final_outcome.clone(),
        last_commit_sha: Some(commit_sha.clone()),
        schema_version_observed: schema_version_observed.clone(),
        error_message: None,
        record_count: records_parsed as i64,
    })?;

    // TI-08 observability: pair the fetch_start event above with a fetch_done
    // event on the success path. The plan 04-04 task 4 feed_no_per_query.rs
    // counts `op="fetch_start"` ONLY (not fetch_done) so the two events stay
    // distinguishable.
    tracing::info!(
        target = "sentinel.feed.fetch",
        op = "fetch_done",
        feed = feed_name,
        outcome = final_outcome,
        records_parsed,
        records_failed,
        "fetch completed",
    );

    Ok(FetchOutcome {
        feed: feed_name.to_string(),
        commit_sha,
        records_parsed,
        records_failed,
        host_iocs_extracted: host_iocs_count,
        schema_version_observed,
        warnings,
    })
}

/// SPIKE-API-VERIFIED: gix 0.83 first-time-clone call chain.
///   1. PrepareFetch::new(url, path, Kind::WithWorktree, defaults, defaults)
///   2. .with_shallow(Shallow::DepthAtRemote(NonZeroU32::new(1)?))
///   3. .fetch_then_checkout(progress::Discard, &AtomicBool) -> (PrepareCheckout, Outcome)
///   4. PrepareCheckout::main_worktree(progress::Discard, &AtomicBool) -> (Repository, Outcome)
fn clone_fresh(
    feed_name: &str,
    url: &str,
    local: &Path,
    interrupt: &AtomicBool,
    deadline: Instant,
    deadline_seconds: u64,
) -> Result<gix::Repository, FeedFetchError> {
    check_deadline(feed_name, deadline, deadline_seconds, interrupt)?;
    let mut prepare = gix::clone::PrepareFetch::new(
        url,
        local,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::default(),
    )
    .map_err(|e| FeedFetchError::Git {
        feed: feed_name.to_string(),
        message: format!("PrepareFetch::new: {e}"),
    })?
    .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
        NonZeroU32::new(1).expect("nonzero"),
    ));
    let (mut checkout, _outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, interrupt)
        .map_err(|e| classify_git_err(feed_name, deadline, deadline_seconds, interrupt, e))?;
    check_deadline(feed_name, deadline, deadline_seconds, interrupt)?;
    let (repo, _checkout_outcome) = checkout
        .main_worktree(gix::progress::Discard, interrupt)
        .map_err(|e| classify_git_err(feed_name, deadline, deadline_seconds, interrupt, e))?;
    Ok(repo)
}

fn head_sha(repo: &gix::Repository) -> Result<String, Box<dyn std::error::Error>> {
    let mut head = repo.head()?;
    let id = head
        .try_peel_to_id()?
        .ok_or("HEAD does not point at object")?;
    Ok(id.to_hex().to_string())
}

fn build_rows_from_parsed(feed_name: &str, p: &ParsedRecord, rows: &mut Vec<FeedIocRow>) -> usize {
    let mut added = 0usize;
    // One row per affected[] block (with host_ioc=None).
    for a in &p.affected {
        rows.push(FeedIocRow {
            feed: feed_name.to_string(),
            advisory_id: p.advisory_id.clone(),
            ecosystem: a.ecosystem.clone(),
            package: a.package.clone(),
            versions_json: a.versions_json.clone(),
            severity: p.severity.clone(),
            tag: p.tag.clone(),
            first_seen_ms: p.published_ms,
            host_ioc: None,
            schema_version_observed: p.schema_version_observed.clone(),
        });
        added += 1;
    }
    // One additional row per (affected_block, host_ioc) — the migration's
    // PRIMARY KEY (feed, advisory_id, ecosystem, package, host_ioc) requires
    // this denormalization so a single advisory carrying both package and
    // host evidence produces both row shapes.
    if !p.host_iocs.is_empty() {
        // If the record has at least one affected block, attach hosts to each
        // (ecosystem, package). If there are no affected blocks (host-only
        // advisory), record one row per host with synthetic (ecosystem="",
        // package="") — these are queryable via host_iocs() only.
        if p.affected.is_empty() {
            for host in &p.host_iocs {
                rows.push(FeedIocRow {
                    feed: feed_name.to_string(),
                    advisory_id: p.advisory_id.clone(),
                    ecosystem: String::new(),
                    package: String::new(),
                    versions_json: "{\"versions\":[],\"ranges\":[]}".to_string(),
                    severity: p.severity.clone(),
                    tag: p.tag.clone(),
                    first_seen_ms: p.published_ms,
                    host_ioc: Some(host.clone()),
                    schema_version_observed: p.schema_version_observed.clone(),
                });
                added += 1;
            }
        } else {
            for a in &p.affected {
                for host in &p.host_iocs {
                    rows.push(FeedIocRow {
                        feed: feed_name.to_string(),
                        advisory_id: p.advisory_id.clone(),
                        ecosystem: a.ecosystem.clone(),
                        package: a.package.clone(),
                        versions_json: a.versions_json.clone(),
                        severity: p.severity.clone(),
                        tag: p.tag.clone(),
                        first_seen_ms: p.published_ms,
                        host_ioc: Some(host.clone()),
                        schema_version_observed: p.schema_version_observed.clone(),
                    });
                    added += 1;
                }
            }
        }
    }
    added
}

fn handle_parse_error(feed_name: &str, e: &FeedParseError, warnings: &mut Vec<FeedWarning>) {
    // Always log to tracing at warn level — full forensic detail goes here
    // regardless of the IPC-warnings cap below, so a malicious-feed scenario
    // still produces a complete audit trail in the unified log.
    match e {
        FeedParseError::SchemaUnknown { observed } => {
            // W-9 structured tracing event — load-bearing for plan 04-04
            // task 3 (feed_schema_unknown_loud.rs) and `log show`-via-tracing
            // observability. The string fields `event = "feed_error"` and
            // `kind = "schema_unknown"` are pinned by acceptance criteria.
            tracing::warn!(
                target = "sentinel.feed.fetch",
                event = "feed_error",
                feed = feed_name,
                kind = "schema_unknown",
                schema_version_observed = ?observed,
                "feed record rejected: schema_version outside accepted range"
            );
        }
        FeedParseError::OversizedRecord { bytes, cap } => {
            tracing::warn!(
                target = "sentinel.feed.fetch",
                event = "feed_error",
                feed = feed_name,
                kind = "oversized_record",
                bytes,
                cap,
                "feed record rejected: oversized"
            );
        }
        other => {
            tracing::warn!(
                target = "sentinel.feed.fetch",
                event = "feed_error",
                feed = feed_name,
                kind = "parse_error",
                error = %other,
                "feed record failed to parse"
            );
        }
    }

    // WR-09 fix: cap the per-feed `feed_warnings` Vec returned over IPC.
    // The cap protects the 64 KiB IPC frame budget against pathological
    // malformed-feed scenarios (50K+ malformed records × ~150 bytes
    // each would overflow). The total Vec length never exceeds
    // `MAX_FEED_WARNINGS_PER_FEED`: we accumulate up to (cap - 1) real
    // warnings, then the next overflow replaces the final slot with a
    // single "truncated" marker, and any further calls are silently
    // dropped. The tracing::warn above always captured full forensic
    // detail regardless of the IPC cap, so a malicious-feed scenario
    // still produces a complete audit trail in the unified log.
    let cap = MAX_FEED_WARNINGS_PER_FEED;
    if warnings.len() < cap.saturating_sub(1) {
        let warning = match e {
            FeedParseError::SchemaUnknown { observed } => FeedWarning {
                feed: feed_name.to_string(),
                kind: "schema_unknown".to_string(),
                message: format!(
                    "schema_version {:?} outside accepted range >=1.4.0,<2.0.0",
                    observed
                ),
            },
            FeedParseError::OversizedRecord { bytes, cap } => FeedWarning {
                feed: feed_name.to_string(),
                kind: "parse_error".to_string(),
                message: format!("oversized record: {bytes} bytes (cap {cap})"),
            },
            other => FeedWarning {
                feed: feed_name.to_string(),
                kind: "parse_error".to_string(),
                message: other.to_string(),
            },
        };
        warnings.push(warning);
    } else if warnings.len() == cap.saturating_sub(1) {
        warnings.push(FeedWarning {
            feed: feed_name.to_string(),
            kind: "truncated".to_string(),
            message: format!(
                "further warnings suppressed (per-feed cap {cap})"
            ),
        });
    }
    // warnings.len() >= cap → silently drop further IPC warnings.
}

fn check_deadline(
    feed_name: &str,
    deadline: Instant,
    deadline_seconds: u64,
    interrupt: &AtomicBool,
) -> Result<(), FeedFetchError> {
    if Instant::now() >= deadline || interrupt.load(Ordering::SeqCst) {
        return Err(FeedFetchError::Timeout {
            feed: feed_name.to_string(),
            seconds: deadline_seconds,
        });
    }
    Ok(())
}

/// WR-02 fix: compare two git URLs after normalization. Both sides are
/// parsed through `gix::url::parse` (which canonicalizes scheme case,
/// host case, default ports, and IPv6 brackets), then we compare the
/// stable component triple `(scheme, host, path-without-trailing-.git)`.
///
/// Why a custom equality rather than `==` on `gix::Url`: `gix::url::parse`
/// preserves the `.git` suffix and any trailing slash on the path
/// verbatim — so a stored origin of
///   https://github.com/ossf/malicious-packages.git
/// compares non-equal to a user-supplied target of
///   https://github.com/ossf/malicious-packages
/// even though both name the same upstream. That false negative would
/// burn ~78s of fresh-clone wall-time on every fetch (the Pitfall 6
/// mitigation becomes a Pitfall 6 amplifier). We strip a single trailing
/// `.git` and trailing slashes from each side before path comparison.
///
/// Returns `false` if either side fails to parse — this conservatively
/// triggers a wipe-and-reclone (previous behavior's failure mode).
fn urls_match(stored: &gix::Url, target: &str) -> bool {
    let target_parsed = match gix::url::parse(target.as_bytes().into()) {
        Ok(u) => u,
        Err(_) => return false,
    };
    // Scheme and host should match after gix's canonicalization (scheme
    // case + default-port stripping etc. handled by gix::url::parse).
    if stored.scheme != target_parsed.scheme {
        return false;
    }
    if stored.host() != target_parsed.host() {
        return false;
    }
    if stored.port != target_parsed.port {
        return false;
    }
    // Path: strip trailing `.git` and trailing `/` so equivalent forms
    // compare equal.
    let s_path = canonicalize_git_path(stored.path.as_ref());
    let t_path = canonicalize_git_path(target_parsed.path.as_ref());
    s_path == t_path
}

/// Strip a single trailing `.git` and any trailing slashes from a git
/// URL path. Operates on the byte buffer that `gix::Url::path` exposes
/// (which is a `BString`).
fn canonicalize_git_path(p: &[u8]) -> Vec<u8> {
    let mut out = p.to_vec();
    // Strip trailing slashes first.
    while out.last() == Some(&b'/') {
        out.pop();
    }
    // Then strip a single trailing `.git`.
    if out.ends_with(b".git") {
        let new_len = out.len() - 4;
        out.truncate(new_len);
    }
    // Strip any further trailing slashes uncovered by the .git removal
    // (handles ".../foo.git/" → ".../foo").
    while out.last() == Some(&b'/') {
        out.pop();
    }
    out
}

// WR-03 fix: removed `total_deadline_seconds` — it always returned the
// worst-case 120s ceiling regardless of which deadline was actually
// applied (60s incremental vs 120s first-run). Every Timeout error
// surfaced "exceeded 120s ceiling" even when the real applied deadline
// was 60s, making JSONL log triage and `feed_metadata.error_message`
// attribution wrong. The actual deadline-seconds value is now threaded
// through `fetch_one_feed` → `fetch_one_feed_impl` → helpers as
// `deadline_seconds: u64`, sourced from `concurrency::fetch_feeds_blocking`
// where the choice between FETCH_DEADLINE_FIRST_RUN and
// FETCH_DEADLINE_INCREMENTAL is made.

fn classify_git_err<E: std::fmt::Display>(
    feed_name: &str,
    deadline: Instant,
    deadline_seconds: u64,
    interrupt: &AtomicBool,
    e: E,
) -> FeedFetchError {
    if Instant::now() >= deadline || interrupt.load(Ordering::SeqCst) {
        return FeedFetchError::Timeout {
            feed: feed_name.to_string(),
            seconds: deadline_seconds,
        };
    }
    FeedFetchError::Git {
        feed: feed_name.to_string(),
        message: e.to_string(),
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic with non-string payload".to_string()
    }
}

/// Spawn a watchdog thread that flips `interrupt` to true at `deadline`
/// (or when `done` is set, whichever comes first).
///
/// WR-05 fix: re-check `done` AFTER observing the deadline-passed
/// condition, before tripping `interrupt`. Without the re-check, this
/// race leaks an `interrupt = true` flag for a successful fetch:
///
///   1. Watchdog reads `done` → false (loop top).
///   2. Main thread completes fetch successfully and calls
///      `done.store(true)`.
///   3. Watchdog observes `Instant::now() >= deadline` (e.g., happy-path
///      fetch took 119s of the 120s ceiling) → branches into the
///      interrupt-store before reading `done` again.
///
/// The local `Arc<AtomicBool>` is dropped after the just-completed
/// `fetch_one_feed_impl` call so the spurious flag is harmless TODAY,
/// but the guarantee was clearly "if done, don't trip interrupt" and
/// the original code violated it. The re-check costs one atomic load.
fn spawn_deadline_watchdog(
    interrupt: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    deadline: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // Poll every 100 ms — keeps the watchdog responsive to early `done`
        // signals (so the daemon doesn't block on a 60s-2min timer when the
        // fetch already finished).
        let tick = Duration::from_millis(100);
        loop {
            if done.load(Ordering::SeqCst) {
                return;
            }
            if Instant::now() >= deadline {
                // WR-05: re-check done so a race with main-thread
                // completion does NOT spuriously trip interrupt for a
                // successful fetch.
                if !done.load(Ordering::SeqCst) {
                    interrupt.store(true, Ordering::SeqCst);
                }
                return;
            }
            std::thread::sleep(tick);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    /// Build a tiny git repo at `path` containing OSV-shaped JSON fixtures.
    /// Each `name -> body` entry becomes a file at `osv/<name>`.
    fn build_fixture_repo(path: &Path, files: &[(&str, &str)]) -> String {
        fn git(dir: &Path, args: &[&str]) -> std::process::Output {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "fetcher-test")
                .env("GIT_AUTHOR_EMAIL", "fetcher-test@example.invalid")
                .env("GIT_COMMITTER_NAME", "fetcher-test")
                .env("GIT_COMMITTER_EMAIL", "fetcher-test@example.invalid")
                .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
                .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
                .output()
                .expect("git invocation failed");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            out
        }
        std::fs::create_dir_all(path).expect("mkdir");
        git(path, &["init", "-q", "-b", "main"]);
        let osv_dir = path.join("osv");
        std::fs::create_dir_all(&osv_dir).expect("mkdir osv");
        for (name, body) in files {
            std::fs::write(osv_dir.join(name), body).expect("write fixture");
        }
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "fixture"]);
        let sha = git(path, &["rev-parse", "HEAD"]);
        String::from_utf8_lossy(&sha.stdout).trim().to_string()
    }

    fn file_url(p: &Path) -> String {
        format!("file://{}", p.canonicalize().expect("canon").display())
    }

    fn open_store() -> (tempfile::TempDir, FeedStore) {
        let dir = tempdir().expect("tempdir db");
        let db = dir.path().join("sentinel.db");
        let _store = crate::rule_store::RuleStore::open(&db).expect("rule store open");
        let fs = FeedStore::open(&db).expect("feed store open");
        (dir, fs)
    }

    const VALID_OSV: &str = r#"{
        "schema_version": "1.7.4",
        "id": "MAL-2026-OK",
        "modified": "2026-01-15T00:00:00Z",
        "published": "2026-01-15T00:00:00Z",
        "summary": "ok",
        "affected": [{"package": {"ecosystem": "npm", "name": "ok-pkg"}, "versions": ["1.0.0"]}]
    }"#;

    const MALFORMED_OSV: &str = r#"{ "schema_version": "1.7.4", broken json"#;

    const SCHEMA_UNKNOWN_OSV: &str = r#"{
        "schema_version": "2.0.0",
        "id": "MAL-2026-NEW-SCHEMA",
        "affected": []
    }"#;

    #[test]
    fn fetcher_first_clone_then_parse_against_fixture() {
        let fixture_dir = tempdir().expect("fixture tempdir");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(
            &fixture_repo,
            &[("MAL-OK.json", VALID_OSV), ("MAL-BAD.json", MALFORMED_OSV)],
        );
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone tempdir");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");

        assert_eq!(outcome.feed, "OSV");
        assert_eq!(outcome.records_failed, 1, "MAL-BAD malformed JSON");
        assert_eq!(outcome.records_parsed, 1, "MAL-OK should parse");
        let rows = store.query_by_pkg("npm", "ok-pkg").expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].advisory_id, "MAL-2026-OK");

        // Metadata recorded.
        let md = store.read_metadata("OSV").expect("read").expect("present");
        assert_eq!(md.last_pull_outcome, "parse_error"); // 1 failed -> parse_error
        assert!(md.last_commit_sha.is_some());
    }

    #[test]
    fn fetcher_incremental_fetch_against_existing_clone() {
        let fixture_dir = tempdir().expect("fixture tempdir");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(&fixture_repo, &[("MAL-OK.json", VALID_OSV)]);
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone tempdir");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        // First run: clone.
        let d1 = Instant::now() + Duration::from_secs(30);
        let _o1 = fetch_one_feed("OSV", &url, &local, d1, 30, &store).expect("first fetch");
        assert!(local.join(".git").exists(), "first run produced .git/");

        // Second run: incremental fetch path. Should complete fast against
        // the same fixture (the existing path is exercised even if no new
        // commits land).
        let started = Instant::now();
        let d2 = Instant::now() + Duration::from_secs(30);
        let o2 = fetch_one_feed("OSV", &url, &local, d2, 30, &store).expect("incremental");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "incremental fetch took {:?} (expected < 10s)",
            started.elapsed()
        );
        assert_eq!(o2.records_parsed, 1);
    }

    #[test]
    fn fetcher_respects_origin_url_change() {
        // First clone from fixture A, then point the fetcher at fixture B and
        // verify the local cache is wiped + re-cloned from B.
        let fixture_a_dir = tempdir().expect("fixture A");
        let fixture_a = fixture_a_dir.path().join("repo");
        let _sha_a = build_fixture_repo(&fixture_a, &[("MAL-A.json", VALID_OSV)]);
        let url_a = file_url(&fixture_a);

        let fixture_b_dir = tempdir().expect("fixture B");
        let fixture_b = fixture_b_dir.path().join("repo");
        let body_b = VALID_OSV.replace("MAL-2026-OK", "MAL-2026-FROM-B");
        let _sha_b = build_fixture_repo(&fixture_b, &[("MAL-B.json", body_b.as_str())]);
        let url_b = file_url(&fixture_b);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let _o1 = fetch_one_feed(
            "OSV",
            &url_a,
            &local,
            Instant::now() + Duration::from_secs(30),
            30,
            &store,
        )
        .expect("fetch A");
        // Now point at fixture B.
        let _o2 = fetch_one_feed(
            "OSV",
            &url_b,
            &local,
            Instant::now() + Duration::from_secs(30),
            30,
            &store,
        )
        .expect("fetch B");

        let rows = store.query_by_pkg("npm", "ok-pkg").expect("query");
        let ids: Vec<String> = rows.iter().map(|r| r.advisory_id.clone()).collect();
        assert!(
            ids.contains(&"MAL-2026-FROM-B".to_string()),
            "expected fixture B's advisory after URL change, got {:?}",
            ids
        );
        // Ideally A's record was deleted because delete_feed runs before
        // upsert; verify.
        assert!(
            !ids.contains(&"MAL-2026-OK".to_string()),
            "fixture A's advisory should have been replaced; got {:?}",
            ids
        );
    }

    #[test]
    fn fetcher_deadline_exceeded_returns_timeout() {
        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(&fixture_repo, &[("MAL-OK.json", VALID_OSV)]);
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        // Already-expired deadline: the very-first check_deadline call inside
        // clone_fresh fires.
        let deadline = Instant::now() - Duration::from_secs(1);
        let err = fetch_one_feed("OSV", &url, &local, deadline, 60, &store).expect_err("must err");
        match err {
            FeedFetchError::Timeout { feed, seconds } => {
                // WR-03: confirm the surfaced deadline-seconds is the value
                // we passed (60), not the previous always-120 hardcoded
                // worst case.
                assert_eq!(feed, "OSV");
                assert_eq!(seconds, 60, "expected configured 60s, got {seconds}");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn fetcher_records_schema_unknown_outcome_when_all_records_fail_schema() {
        // TI-06 surfacing pin: when EVERY parse failure is SchemaUnknown and
        // zero records succeed, last_pull_outcome must be "schema_unknown" —
        // not the generic "parse_error". Plan 04-04 task 3 fix.
        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(
            &fixture_repo,
            &[("MAL-NEW.json", SCHEMA_UNKNOWN_OSV)],
        );
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");
        assert_eq!(outcome.records_parsed, 0);
        assert_eq!(outcome.records_failed, 1);

        let md = store.read_metadata("OSV").expect("read").expect("present");
        assert_eq!(
            md.last_pull_outcome, "schema_unknown",
            "all-schema-unknown failures must surface as 'schema_unknown' outcome"
        );
        // schema_version_observed surfaces what was rejected so users can
        // see "we got 2.0.0; sentinel knows >=1.4.0,<2.0.0".
        assert_eq!(
            md.schema_version_observed.as_deref(),
            Some("2.0.0"),
            "schema_version_observed must capture the rejected version"
        );
    }

    #[test]
    fn fetcher_records_schema_unknown_warning() {
        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(
            &fixture_repo,
            &[("MAL-NEW.json", SCHEMA_UNKNOWN_OSV), ("MAL-OK.json", VALID_OSV)],
        );
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");
        assert_eq!(outcome.records_failed, 1, "schema_unknown counts as failure");
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.kind == "schema_unknown"),
            "expected schema_unknown warning, got {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn fetcher_too_many_failures_keeps_last_good_cache() {
        // Pre-seed last-good rows, then run a fetch where ALL records are
        // malformed (>50% threshold). Last-good rows must remain.
        let (_db_dir, store) = open_store();
        store
            .upsert_iocs(&[FeedIocRow {
                feed: "OSV".to_string(),
                advisory_id: "MAL-PRE-EXISTING".to_string(),
                ecosystem: "npm".to_string(),
                package: "pre-existing".to_string(),
                versions_json: "{}".to_string(),
                severity: None,
                tag: None,
                first_seen_ms: 0,
                host_ioc: None,
                schema_version_observed: "1.7.4".to_string(),
            }])
            .expect("seed");

        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(
            &fixture_repo,
            &[("a.json", MALFORMED_OSV), ("b.json", MALFORMED_OSV)],
        );
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");
        assert_eq!(outcome.records_parsed, 0);
        assert!(outcome.records_failed >= 2);

        // Pre-existing row remains.
        let rows = store.query_by_pkg("npm", "pre-existing").expect("query");
        assert_eq!(rows.len(), 1, "last-good cache must be retained per D-87");

        let md = store.read_metadata("OSV").expect("read").expect("present");
        assert_eq!(md.last_pull_outcome, "parse_error");
    }

    #[test]
    fn fetcher_caps_per_feed_warnings_with_truncated_marker() {
        // WR-09 fix: feed many malformed records (well above the cap) and
        // verify the resulting `feed_warnings` Vec is bounded at
        // MAX_FEED_WARNINGS_PER_FEED with a single trailing "truncated"
        // marker. This protects the 64 KiB IPC frame from pathological
        // malformed-feed inflation.
        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        // 20 malformed records is well above MAX_FEED_WARNINGS_PER_FEED (8).
        let mut files: Vec<(String, &str)> = (0..20)
            .map(|i| (format!("MAL-BAD-{i:02}.json"), MALFORMED_OSV))
            .collect();
        let files_ref: Vec<(&str, &str)> =
            files.iter_mut().map(|(n, b)| (n.as_str(), *b)).collect();
        let _sha = build_fixture_repo(&fixture_repo, &files_ref);
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");

        // Many records failed.
        assert!(outcome.records_failed >= 20);
        // But the IPC-bound warnings vec is capped.
        assert_eq!(
            outcome.warnings.len(),
            MAX_FEED_WARNINGS_PER_FEED,
            "warnings must be capped at {} (got {})",
            MAX_FEED_WARNINGS_PER_FEED,
            outcome.warnings.len(),
        );
        // The last warning is the truncated marker.
        let last = outcome.warnings.last().expect("at least one warning");
        assert_eq!(last.kind, "truncated", "last warning is the truncated marker");
        assert!(
            last.message.contains("suppressed"),
            "truncated message mentions suppression: {:?}",
            last.message,
        );
        // Earlier warnings are NOT truncated markers (i.e., real entries).
        for (i, w) in outcome.warnings[..MAX_FEED_WARNINGS_PER_FEED - 1].iter().enumerate() {
            assert_ne!(
                w.kind, "truncated",
                "warning at position {i} should be a real entry, not the marker"
            );
        }
    }

    /// WR-04 regression: a record with valid schema but zero affected
    /// blocks AND zero host_iocs (e.g., a withdrawn advisory that's still
    /// shipped in the feed) must NOT bump `records_parsed` from 0 to 1 via
    /// the previous `.max(1)` floor — otherwise mixing one such empty
    /// record with one schema_unknown failure suppresses the
    /// `last_pull_outcome = "schema_unknown"` reclassification and the
    /// generic "parse_error" surfaces instead.
    const EMPTY_VALID_OSV: &str = r#"{
        "schema_version": "1.7.4",
        "id": "MAL-2026-EMPTY",
        "modified": "2026-01-15T00:00:00Z",
        "published": "2026-01-15T00:00:00Z",
        "summary": "withdrawn",
        "affected": []
    }"#;

    #[test]
    fn fetcher_empty_valid_record_does_not_inflate_records_parsed() {
        let fixture_dir = tempdir().expect("fixture");
        let fixture_repo = fixture_dir.path().join("repo");
        let _sha = build_fixture_repo(
            &fixture_repo,
            &[
                ("MAL-EMPTY.json", EMPTY_VALID_OSV),
                ("MAL-NEW.json", SCHEMA_UNKNOWN_OSV),
            ],
        );
        let url = file_url(&fixture_repo);

        let clone_dir = tempdir().expect("clone");
        let local = clone_dir.path().join("clone");
        let (_db_dir, store) = open_store();

        let deadline = Instant::now() + Duration::from_secs(30);
        let outcome = fetch_one_feed("OSV", &url, &local, deadline, 30, &store).expect("fetch");

        // The empty-but-valid record contributes 0 rows; the schema-unknown
        // record fails. records_parsed must stay 0 so the
        // all_failures_schema_unknown gate still fires.
        assert_eq!(
            outcome.records_parsed, 0,
            "empty valid record must not bump records_parsed (WR-04)"
        );
        assert_eq!(outcome.records_failed, 1);

        let md = store.read_metadata("OSV").expect("read").expect("present");
        assert_eq!(
            md.last_pull_outcome, "schema_unknown",
            "with WR-04 fixed, all-failures-schema-unknown reclassification \
             must NOT be suppressed by an empty-but-valid sibling record"
        );
    }

    #[test]
    fn urls_match_handles_dotgit_suffix_difference() {
        // WR-02 fix: a stored origin of `.../malicious-packages` should match
        // a target of `.../malicious-packages.git` (and vice versa) after
        // normalization. gix's parser treats both as the same URL.
        let stored = gix::url::parse(
            "https://github.com/ossf/malicious-packages.git".as_bytes().into(),
        )
        .expect("parse stored");
        let target = "https://github.com/ossf/malicious-packages";
        assert!(
            urls_match(&stored, target),
            "stored .git suffix should match target without .git"
        );

        let stored2 =
            gix::url::parse("https://github.com/ossf/malicious-packages".as_bytes().into())
                .expect("parse stored2");
        let target2 = "https://github.com/ossf/malicious-packages.git";
        assert!(
            urls_match(&stored2, target2),
            "stored without .git should match target with .git"
        );
    }

    #[test]
    fn urls_match_rejects_genuinely_different_urls() {
        // A different host should NOT match — wipe-and-reclone is correct here.
        let stored =
            gix::url::parse("https://github.com/ossf/malicious-packages".as_bytes().into())
                .expect("parse");
        let target = "https://github.com/github/advisory-database.git";
        assert!(!urls_match(&stored, target), "different repos must not match");
    }

    #[test]
    fn urls_match_rejects_unparseable_target() {
        // An unparseable target conservatively returns false (triggers
        // wipe+reclone) rather than panicking.
        let stored =
            gix::url::parse("https://github.com/ossf/malicious-packages".as_bytes().into())
                .expect("parse");
        assert!(!urls_match(&stored, "::not a url::"));
    }

    #[test]
    fn url_override_for_reads_per_feed_env_var() {
        // Use unique sentinel names so concurrent test runs don't stomp.
        // SAFETY: env mutation in tests is acceptable as set/unset are
        // process-local and cargo runs tests in parallel within the same
        // process — but `OSV` and `GHSA` don't collide here because we restore.
        unsafe {
            std::env::set_var("SENTINEL_FEED_URL_OVERRIDE_OSV", "file:///tmp/test-osv");
        }
        assert_eq!(
            url_override_for("OSV").as_deref(),
            Some("file:///tmp/test-osv")
        );
        unsafe {
            std::env::remove_var("SENTINEL_FEED_URL_OVERRIDE_OSV");
        }
        assert_eq!(url_override_for("OSV"), None);

        // Unknown feed name returns None without panic.
        assert_eq!(url_override_for("UNKNOWN"), None);
    }
}
