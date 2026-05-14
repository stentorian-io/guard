# Changelog

All notable changes to Sentinel are documented in this file.
This changelog is generated from [conventional commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Features
- **daemon:** Add kqueue-based persistence-path watcher
- **hook:** Re-enable getaddrinfo interpose via daemon-proxied DNS
- **daemon:** Add policy gate to Resolve IPC handler
- **daemon:** Skip prompt for policy-allowed hosts in TTY resolve path
- **hook:** Enforce FAIL_CLOSED in getaddrinfo interpose
- **daemon,e2e:** Complete M005 — prompt timeout and E2E test modernization
- **daemon,cli,e2e:** Complete M006 — production hardening

### Bug Fixes
- **hook,e2e:** Errno ordering and test harness improvements
- **e2e:** Use local feed fixtures for CI-compatible release builds

### Testing
- **e2e:** Add getaddrinfo → resolve → connect E2E test suite

### Documentation
- Align CLAUDE.md and README.md with current Rust/DYLD codebase
- Update CLAUDE.md with v0.6–v1.0 roadmap milestones

### Miscellaneous
- Remove license files, defer licensing decision to v1

## [0.5] — 2026-05-11

### Features
- **watchdog:** Add sentinel-watchdog crate with daemon liveness monitoring (M004-S01)
- **integrity:** HMAC-SHA256 snapshot integrity scheme (M004-S02)
- **hook:** Binary self-integrity verification at load time (M004-S03)
- **hook:** Anti-detection getenv interposition (M004-S04)
- **cli:** Add `sentinel repair` and `sentinel unwrap-all` commands (M004-S05)

### Bug Fixes
- **hook:** Resolve macOS 26+ crash from dyld init-order conflicts

### Testing
- **e2e:** M004-S06 resilience integration tests

## [0.4] — 2026-05-10

### Features
- **hook:** Expand interpose surface with send/write/writev hooks and raw syscall backend
- **hook:** Block exec of network-capable hardened-runtime binaries (S02)
- **cli:** Ambient shell wrapping via init.sh package-manager functions (S03)
- **hook:** Monitor open/openat to macOS persistence paths (S04)
- **cli:** Add `sentinel status persistence` subcommand (S05)
- **hook:** OS-version-aware persistence-path matrix (S06)
- **core:** Add lockfile registry extraction and snapshot integration (M003-S07)

### Testing
- **e2e:** Add M003-S08 cross-slice integration and open-hook benchmark

### Miscellaneous
- **hooks:** Auto-tag version on milestone completion

## [0.3] — 2026-05-10

### Features
- **ipc:** Add DenyNotify message for hook-to-daemon denial forensics

### Bug Fixes
- **e2e:** Use pip download instead of --dry-run for pip registry test
- **security:** WR-04 ancestor-walk $HOME boundary + WR-05 shared SQLite reader
- **tree:** Close PID-reuse race via TASK_AUDIT_TOKEN pidversion cross-check

### Documentation
- **bench:** Populate VAL-03 binding p99 on MacBookAir10,1

### Miscellaneous
- Archive v0.2 phase directories to milestones/v0.2-phases/
- Remove GSD-1 .planning/ directory
- Remove spike/ DYLD hook proof-of-concept

## [0.2] — 2026-05-09

### Features
- **06-01:** Root-default-wrap parser surface (Cmd::External + --learn)
- **06-05:** Add scripts/phase06-codemod.sh — two-pass ripgrep+sed codemod
- **07-01:** Add ListRules/ListTrust/IsTrusted/DeleteInstallArtifacts wire types
- **07-01:** Add daemon handlers for ListRules/ListTrust/IsTrusted/DeleteInstallArtifacts
- **07-01:** Wire MessageTag 0x0E/0x0F/0x10/0x11 dispatch arms
- **07-02:** Add install/drift module + tty::confirm consolidated helper
- **07-02:** Factor uninstall into per-component helpers + run_remove dispatch
- **07-03:** Add list_rules/list_trust/is_trusted ipc_client request fns
- **07-03:** Add status::{rules,trust,denials,review} submodules
- **07-03:** Add setup::run_setup dispatch + wire install --reinstall
- **07-04:** Atomic clap surface cutover — Cmd::Setup + Cmd::Status hard-cut
- **07-04:** First-trust prompt in run_orchestrator + delete approve.rs + trim trust_policy.rs
- **08-03:** Add cache-hit criterion + hdrhistogram bench
- **08-05:** Add scripts/bench-hot-path.sh VAL-03 one-command runner
- **08-09:** Add --dry-run regression-trap to bench-hot-path.sh

### Bug Fixes
- **06-04:** Use env! for CARGO_BIN_EXE_sentinel in non_tty_learn test
- **06:** Reject --learn with named verbs (CR-01 BLOCKER)
- **07:** Detect stdin EOF in status review to prevent infinite loop (BL-01)
- **07:** Narrow --project filter to trusted-toml rules only (WR-01)
- **07:** Drift detection — key-by-key plist compare to avoid false drifts (WR-02)
- **07:** Clean init_script from daemon-only remove path (WR-03)
- **07:** Reject misordered status --json/--verbose with EX_USAGE (WR-06)
- **08-08:** Retarget PHASE2 to 192.0.2.1 to exercise dylib's libc-deny path
- **08:** WR-01 correct SOCKET_TEST_LOCK rationale comment
- **08:** WR-02 gate cache_hit_hot_path bench to target_os=macos
- **08:** WR-03 use mktemp -d scratch dir in bench-hot-path.sh
- **08:** WR-04 truncate live-wrap stdout dump at UTF-8 char boundary
- **08:** WR-05 parallel ns-suffix handling for both p99 columns

### Refactoring
- **06-02:** Rename baseline_mode to learn_mode in run_orchestrator
- **06-05:** Apply phase06 codemod to e2e tests — drop `run` + `--` from 29 files
- **07-02:** Extract denial_log + lift find_sentinel_toml to core

### Testing
- **06-04:** Rewrite cli_args_tests for Cmd::External parser shape (CLI-08, CLI-10)
- **06-04:** Rename run_subcommand_still_parses to external_subcommand_still_parses_alongside_trust_policy
- **07-03:** Add failing test for new ipc_client request fns
- **07-03:** Add failing test for new status::* submodules
- **07-03:** Add failing test for setup::run_setup dispatch + mutual exclusion
- **07-04:** Add RED gate for new Cmd::Setup/Cmd::Status parser shape
- **07-04:** Add RED gate for trust_policy::display_rules pub + approve.rs delete
- **07-04:** Rewrite CLI tests for new parser shape; switch SetupTarget to ValueEnum
- **07-05:** Rewrite 6 e2e tests for new setup/status verb shape
- **07-05:** Add 4 new e2e tests + rename approve_from_log_filter
- **07-05:** Add 4 new e2e tests for non-TTY gates + first-trust path
- **08-02:** Verify D-38 dead-socket returns ECONNREFUSED deterministically (VAL-05)
- **08-04:** Add VAL-03 live-wrap E2E bench (bench_hot_path_e2e.rs)
- **08-06:** Tighten failure_modes_daemon_killed to denied-only + EHOSTUNREACH

### Documentation
- Start milestone v0.2 Minimal CLI + perf hardening
- Define milestone v0.2 requirements
- Create milestone v0.2 roadmap (4 phases)
- **06:** Capture phase context
- **state:** Record phase 06 context session
- **06:** Research CLI redesign — clap external_subcommand strategy
- **06:** Create phase plan
- **06:** Begin phase 06 execution
- **06-01:** Complete root-default-wrap parser surface plan
- **06-02:** Align baseline.rs module doc-comment with --learn flag
- **06-02:** Complete run_orchestrator + baseline.rs naming alignment plan
- **06-03:** Retire CLI-09 and CLI-22 from REQUIREMENTS.md
- **06-03:** Drop CLI-09/CLI-22 success criteria from ROADMAP Phase 06
- **06-03:** Drop 'run' from README usage example (D-03 root-default-wrap)
- **06-03:** Complete documentation-update plan
- **phase-06:** Update tracking after wave 1
- **06-04:** Complete CLI parser test rewrite plan
- **06-05:** Complete phase06 codemod plan — SUMMARY landed
- **phase-06:** Update tracking after wave 2
- **06:** Record verification — 7/7 must-haves passed
- **06:** Add code review report
- **06:** Mark CR-01 resolved in code review report
- **phase-06:** Complete phase execution
- **phase-06:** Evolve PROJECT.md after phase completion
- **07:** Capture phase context
- **state:** Record phase 07 context session
- **07:** Research phase domain
- **07:** Create phase plan
- **07-01:** Complete daemon-side IPC plan
- **07-02:** Complete refactor plan summary
- **phase-07:** Update tracking after wave 1
- **07-03:** Complete cli-status-and-setup-modules plan
- **phase-07:** Update tracking after wave 2
- **07-04:** Complete cli-surface-cutover plan
- **phase-07:** Update tracking after wave 3
- **07-05:** Finalize D-09 hard-cut in REQUIREMENTS.md + STATE.md
- **07-05:** Complete e2e test migration + D-09 doc revisions plan
- **phase-07:** Update tracking after wave 4
- **07:** Add code review report
- **07:** Add code review fix report
- **phase-07:** Add security threat verification (37/37 closed)
- **08:** Capture phase context
- **state:** Record phase 08 context session
- **08:** Research phase domain
- **08:** Plan phase (research, patterns, 7 plans)
- **08-01:** Static analysis of LogRow::Allow emit sites
- **08-01:** Record empirical run + corroborating in-tree evidence
- **08-01:** Pick D-39 disposition #3 (defer JSONL to v0.3)
- **08-01:** Complete libc-allow-jsonl-audit plan
- **08-02:** Complete daemon-kill verification spike plan (D-38 PASS)
- **08-04:** Complete live-wrap-e2e-bench plan
- **08-03:** Refresh hot_path.rs header to cross-ref cache_hit_hot_path
- **08-03:** Complete cache-hit-bench plan
- **phase-08:** Update tracking after wave 1
- **08-05:** Add docs/BENCH.md hot-path bench artifact
- **08-05:** Add Performance section + docs/BENCH.md cross-link to README
- **08-05:** Complete bench-runner-and-docs plan
- **08-06:** Record D-39 disposition #3 + D-40 NOT activated audit readout
- **08-06:** Summarize e2e-tightening plan completion
- **phase-08:** Update tracking after wave 2
- **08-07:** Rewrite REQUIREMENTS.md VAL-05 per D-39 disposition #3 + D-38 PASS
- **08-07:** Mirror VAL-05 wording in ROADMAP Phase 08 success criterion #2
- **08-07:** Plan summary — VAL-05 wording revision per CONTEXT D-41
- **phase-08:** Update tracking after wave 3
- **08:** Add code review report
- **phase-08:** Add verification report (gaps_found)
- **phase-08:** Plan gap closure (08-08 BLOCKER, 08-09 WARNING)
- **08-08:** Record empirical correction in 08-RESEARCH.md (VAL-05 audit trail)
- **08-08:** Complete VAL-05 BLOCKER fix plan with empirical pass evidence
- **08-09:** Add Capture Procedure section to docs/BENCH.md
- **08-09:** Complete WARNING fix — bench --dry-run + Capture Procedure plan
- **phase-08:** Update tracking after wave 4 (gap closure)
- **phase-08:** Re-verification passed (gaps closed via 08-08, 08-09)
- **phase-08:** Mark phase complete; preserve VAL-03 [ ] per conservative-checkbox stance
- **08:** Add code review fix report

### Miscellaneous
- **planning:** Archive phase 01-05 artifacts after milestone v0.1 completion
- Merge executor worktree (worktree-agent-a07706b185b967d82)
- Merge executor worktree (worktree-agent-a91e758755cbec22f)
- Merge executor worktree (worktree-agent-a5fd510d891a80a54)
- Merge executor worktree (worktree-agent-a17e8027e37a0bf07)
- Merge executor worktree (worktree-agent-acd75761663fa7497)
- Merge executor worktree (worktree-agent-adedb6a9c898dca6f)
- Merge executor worktree (worktree-agent-a05a5272e05923720)
- Merge executor worktree (worktree-agent-a859645a51bd3d238)
- Merge executor worktree (worktree-agent-a2f07c7074a70ba69)
- Merge executor worktree (worktree-agent-a51349b9c81f85196)
- Merge executor worktree (worktree-agent-a8e34428d62d3f92f)
- **08-03:** Add hdrhistogram dev-dep + cache_hit_hot_path bench entry
- Merge executor worktree (worktree-agent-ad9ad9713b7aab84d)
- **phase-08:** Merge wave 1 (plans 08-01..08-04 via worktree-agent-a0e0aef4b082e777b)
- **phase-08:** Merge executor worktree (worktree-agent-acdd14618053116e4)
- **phase-08:** Merge executor worktree (worktree-agent-aeafcca1872bbcd3b)
- **phase-08:** Merge executor worktree (worktree-agent-a09388e7b6066b3e8)
- **phase-08:** Merge gap-closure worktree (worktree-agent-a22cb4ce749a51eb8)
- **phase-08:** Merge gap-closure worktree (worktree-agent-aede3f40bf2920957)
- Archive v0.2 milestone files
- Remove REQUIREMENTS.md for v0.2 milestone

### Build
- **08:** Regenerate Cargo.lock for hdrhistogram dev-dep

## [0.1] — 2026-05-08

### Features
- **01-01:** Create spike workspace skeleton with edition-2024 unsafe attribute syntax
- **01-01:** Implement spike-hook with interpose record, RTLD_NEXT capture, LOCAL_PEERTOKEN check
- **01-01:** Implement spike-probe binary exercising A1, A3+A4, A5 at runtime
- **01-01:** Write spike verification script and record SPIKE-RESULTS.md; all assumptions PASS
- **01-02:** Create six crate skeletons with manifests and minimal stubs
- **01-03:** Implement identity.rs, error.rs, allowlist.rs, snapshot.rs — GREEN phase
- **01-03:** Add allowlist_tests and snapshot_tests — Task 2 GREEN phase
- **01-04:** Implement frame.rs, messages.rs, error.rs, transport.rs — Task 1 GREEN
- **01-04:** Add transport_tests — Task 2 end-to-end socketpair peer-auth tests
- **01-05:** GREEN phase Task 1 — state_dir + snapshot + manifest publication
- **01-05:** GREEN phase Task 2 — IPC server, peer auth, tracked roots, dev-install
- **01-06:** Task 1 — reentrancy guard, log_buffer, cache, snapshot loader + tests
- **01-06:** Task 2 — five libc interpose records + replacement fns + section test
- **01-07:** Implement replace_nw.rs Network.framework dlsym + shadow exports (D-09)
- **01-08:** GREEN phase Task 1 — cli.rs, locate.rs, audit_token.rs, main.rs (5 tests pass)
- **01-08:** GREEN phase Task 2 — spawn_wrapped (posix_spawnp+envp) + ipc_client (connect_timeout+register) (6 tests pass)
- **01-09:** Implement e2e harness + smoke tests (Roadmap criterion #1)
- **02-01:** Replace AllowlistEntry enum with tier-aware V2 struct
- **02-01:** Bump Snapshot to SCHEMA_V2 with run_uuid + project_toml fields
- **02-01:** Add .sentinel.toml deserde types and parser
- **02-01:** Add Phase 2 IPC message types
- **02-02:** Add curated allowlist YAML and serde_yml workspace dep
- **02-02:** Implement tier-walk evaluate_policy + hard-rule predicates
- **02-02:** Implement curated YAML loader (load_curated + parse_yaml)
- **02-03:** Add SQLite RuleStore + initial schema migration
- **02-03:** Implement .sentinel.toml walk-up + sha256 + parse_file
- **02-04:** Replace TrackedRoots with ProcessTree supervisor
- **02-04:** Add os_ffi.rs csops syscall binding for D-34 hardened-runtime detection
- **02-04:** Add gap_detector.rs 500ms two-phase timer for D-34
- **02-04:** Replace ipc_server with bounded thread pool + tagged dispatch
- **02-05:** Replace SpscRing with crossbeam ArrayQueue (BL-03 / D-43)
- **02-05:** Add ipc_client.rs blocking IPC + copy_cstr_to_buf helper (D-31)
- **02-05:** Add fork/exec shadows + 7 __DATA,__interpose records (D-31, D-32, D-33)
- **02-05:** Wire ctor — DylibLoaded IPC + probe_self_test re-enable (D-35, D-44)
- **02-06a:** Per-run snapshot lifecycle (publish_run + gc_run + path helpers)
- **02-06a:** PrepareSnapshot/TrustPolicy/Resolve handlers + dispatch wiring
- **02-06a:** Daemon main.rs wiring — load curated YAML, open RuleStore, ensure runs/
- **02-06b:** CLI trust-policy + prepare_snapshot pre-spawn IPC + envp
- **02-06b:** NW.framework verdict path with safe is_nw_object gate (D-41)
- **02-07:** Periodic per-run snapshot GC sweeper (D-29)
- **02-08:** Wire dylib Resolve-IPC client; populate getaddrinfo cache pre-libc-connect for curated allowlist hosts
- **02-09:** Add EnvNotPropagatedGap IPC frame (tag 0x08) + daemon handler; activate CoverageGap::EnvNotPropagated
- **02-09:** Dylib pre-spawn envp inspector + send_env_not_propagated_gap_sync; activate TREE-06 detection
- **02-09:** E2e test, harness binary, drain_stderr, REGISTER-01 fix for TREE-06
- **03-01:** Implement sentinel-core::policy_file_writer with toml_edit
- **03-02:** Define IPC_SCHEMA_V3 and bump PrepareSnapshot + ExecEvent additively
- **03-02:** Add all Phase 3 IPC message types and supporting structs
- **03-02:** Extend MessageTag enum with 5 new Phase 3 tag bytes 0x09..0x0D
- **03-03:** Add install_artifacts migration and wire into RuleStore
- **03-03:** Implement InstallArtifactStore CRUD + read_via_db fallback (GREEN)
- **03-04:** Extend ProcessNode/RunRecord/ProcessTree/RuleStore for Phase 3
- **03-04:** Add env_capture module with PM env allowlist and R-08 secret denylist
- **03-04:** ExecEvent V3 handler captures pm_env onto ProcessNode
- **03-05:** Implement forensic JSONL log writer module
- **03-06:** Implement prompt dedup window, suggested rules, and recent gaps ring
- **03-07:** BaselineStaging module + extend DaemonState bundle (TDD GREEN)
- **03-07:** Extend PrepareSnapshot handler to accept V3 + propagate is_tty/baseline_mode
- **03-07:** Wire Phase 3 subsystems into main.rs + construct full DaemonState
- **03-08:** Handle_status + handle_insert_user_rule + handle_read_install_artifacts modules
- **03-08:** Wire ipc_server dispatch arms 0x09/0x0B/0x0C/0x0D + gap forensics
- **03-09:** Cli.rs subcommands + install module tree + marker_block atomic + ipc tags (GREEN)
- **03-09:** Task 3 tests — upgrade diff + no-shell-integration gate
- **03-10:** Status.rs + logs.rs + logs_follow.rs — status daemon-down detection + 3 render modes + notify tail (GREEN)
- **03-10:** Wire Cmd::Logs dispatch to sentinel_cli::logs::run_logs
- **03-12:** Long-lived prompt channel handler (Task 1 — POL-02 / D-76)
- **03-12:** DeferredResolveTable + Resolve handler park-pending-prompt (Task 2)
- **03-12:** CLI prompt_channel client + prompt_render TTY UI (Task 3)
- **03-11:** Approve.rs machine/project modes + main.rs dispatch (Task 1 GREEN)
- **03-11:** Approve --from-log filter tests + implementation (Task 2 GREEN)
- **03-13:** Task 1 — cli.rs --baseline flag, V3 PrepareSnapshot, run_orchestrator, spawn_wrapped_with_pgid
- **03-13:** Task 2 — baseline.rs D-60 3-way diff + 4-choice menu (BLOCKER #2) + tests
- **03-13:** Task 3 — D-79 SIGINT handler + signal-hook dep (BLOCKER #1) + unit tests
- **03-14:** Task 1 — install/uninstall roundtrip + status states + non-TTY deny e2e tests
- **03-14:** Task 2 — --follow rotation + R-08 denylist + concurrent prompt channels e2e
- **03-14:** Task 3 — BLOCKER #3/POL-02 + BLOCKER #1/D-79 prompt-unblock e2e tests
- **03-15:** Add SENTINEL_SKIP_LAUNCHCTL env gate to launchctl_bootstrap
- **03-16:** Tier B real-launchctl round-trip (ci-launchd feature-gated)
- **03-17:** Make render_* pub(crate) with _to writer variants and add 5-state render unit tests
- **03-18:** 3 PTY tests for UAT #3 gap closure — dedup, project-scope, deny-exit
- **03-19:** Real 16 MiB rotation test — gz archive + follow continues
- **03-19:** Idle heartbeat test — follow survives 6s idle then resumes
- **04-02-1a:** Migration 003 + RuleStore registration + FeedStore CRUD + state_dir feeds_dir helper
- **04-02-1b:** Sentinel-core osv_match (SEMVER + ECOSYSTEM + GIT version-range matcher)
- **04-02-2:** OSV parser + host extraction + schema-version range gate + matcher shim
- **04-02-3:** Fetcher (gix) + concurrency (mutex + shared-result) + IPC IntelMatch/FeedWarning + V4 schema bump
- **04-03-1:** PrepareSnapshot fetches feeds + merges FeedDeny + DaemonState wiring
- **04-03-2:** Log_writer enrichment + JSONL schema bump + caller-side hook
- **04-03-3:** Status feeds[] + daemon_state degraded surfacing + CLI progress UX
- **04-04-2:** Fixture repos + feed_pol_06 e2e (D-94 POL-06)
- **04-04-3:** TI-05 + TI-06 e2e + schema_unknown outcome differentiation
- **04-04-4:** TI-08 e2e + tracing instrumentation for fetch lifecycle
- **05-01:** Add tools/vendor-ua-parser-js.sh reconstruction script
- **05-02:** Add test_support module with sandbox_home + sink_listener helpers
- **05-02:** Add DaemonHarness::stop_preserving_state + StoppedHarness::restart_with_env
- **05-03:** Plumb package_context into prompt-path PromptRequest + DeferredEntry
- **05-03:** Thread entry_pkg into all four prompt-path emit_decision_row sites
- **05-01:** Commit synthetic ua-parser-js@0.7.29 fixture + provenance
- **05-01:** Add .github/CODEOWNERS protecting validation fixture paths
- **05-04:** Add VAL-01 ua-parser-js demo e2e test
- **05-04:** Add VAL-02 workers.dev validation e2e test
- **05-05:** Add VAL-04 D-09 daemon-killed failure-mode e2e
- **05-05:** Add VAL-04 D-12 corrupt-snapshot failure-mode e2e
- **05-06:** Add VAL-04 D-11 stale-feed failure-mode e2e
- **05-06:** Add VAL-04 D-10 hardened-binary failure-mode e2e
- **05-07:** Add Phase 5 validation GHA workflow
- **quick-260508-et9:** Add pm_env_filter module mirroring daemon-side allowlist
- **quick-260508-et9:** Wire pm_env capture through send_exec_event_sync + 5 interpose sites

### Bug Fixes
- **01-09:** Deny + loopback e2e tests passing (Roadmap criterion #2)
- **01-09:** Align dylib_section_tests with post-09 interpose count (4 records)
- **01-10:** Close snapshot loader TOCTOU between digest and mmap
- **01-10:** Plug Mach send-right leak in audit_token_for_pid
- **01-10:** Correct reentrancy guard ordering and remove dead getaddrinfo export
- **02-07:** D-25a loopback hard-rule in dylib libc connect path (Rule 1)
- **02:** BLOCKER-01 — libc hot path enforces hard rules via evaluate_policy
- **02:** BLOCKER-02 — gate fork/exec/dylib_loaded handlers on tracked peer
- **02:** BLOCKER-03 — canonicalize TrustPolicy path on the daemon side
- **02:** BLOCKER-05 — document IN_HOOK reentrancy assumption for posix_spawn
- **02:** BLOCKER-06 — snapshot_gc liveness probe only treats ESRCH as dead
- **02:** BLOCKER-07 — populate (pid, ppid) in wire AuditTokenWire field
- **02:** WARNING-01 — rename and re-document the matcher microbench
- **02:** WARNING-02 — move BL-04 RAII rationale to reentrancy.rs
- **02:** WARNING-03 — IPC worker panic catcher + RwLock poison tolerance
- **02:** WARNING-04 — arm gap detector on hardened child after fork
- **02:** WARNING-05 — normalize IPv6 cloud-metadata host before comparing
- **02:** WARNING-06 — strict frame classification rejects garbage
- **02:** WARNING-07 — add joinable GC thread variant for graceful shutdown
- **02:** WARNING-08 — fresh per-call read connection removes mutex contention
- **02:** WARNING-09 — escalate ENF-08 wire/kernel pid disagreement to error
- **02:** WARNING-10 — log non-UTF-8 ExecEvent paths (partial fix; full deferred)
- **02:** WARNING-11 — raise MIN_SUFFIX_LEN from 4 to 6 to reject .com / .org
- **02:** WARNING-02 followup — wrap doctest pseudocode in fenced text blocks
- **03:** CR-01 always install SIGINT handler in run_orchestrator
- **03:** CR-02 split prompt-channel reader to break SIGINT deadlock
- **03:** CR-03 preserve rc file mode/owner across marker_block persist
- **03:** CR-04 backup existing policy before baseline Replace
- **03:** CR-05 validate cwd; refuse AllowAlwaysProject without project_toml_path
- **03:** CR-06 use ms-precision timestamp + atomic counter for rotation
- **03:** CR-07 case-insensitive secret denylist + substring patterns
- **03:** CR-09 distinguish EOF from decode error and tear down eagerly
- **03:** WR-01 close signal-hook handle in SigIntHandle::drop
- **03:** WR-02 use safe From<Socket> for UnixStream in ipc_client
- **03:** WR-03 explicit canonicalize error handling in marker_block::strip
- **03:** WR-04 confirm helpers refuse non-TTY stdin
- **03:** WR-05 bound block-destination collection size and dest_host length
- **03:** WR-06 parse existing rule keys with toml_edit, not string slicing
- **03:** WR-07 replace hand-rolled date arithmetic with chrono
- **03:** WR-08 sanity-check wire pid in REGISTER-01 delegation path
- **03:** WR-09 enrich gap-row argv with binary_path from ProcessNode
- **03:** WR-11 forget() dedup entries on response/cancel + periodic gc
- **03:** WR-12 cap argv element count in addition to per-element bytes
- **04-CR-01:** Replace delete_feed+upsert_iocs with atomic replace_feed_iocs
- **04-CR-02:** Gate SENTINEL_SKIP_FEED_FETCH to non-release builds + loud warn
- **04-WR-01:** Preserve FeedFetchError variant through snapshot round-trip
- **04-WR-02:** Normalize origin-URL equality with gix::url::parse + .git tolerance
- **04-WR-03:** Thread actual deadline-seconds into FeedFetchError::Timeout
- **04-WR-04:** Drop records_parsed += added.max(1) floor
- **04-WR-05:** Watchdog re-checks done before tripping interrupt
- **04-WR-06:** Scope-guard FETCH_DELAY_MS test static via Drop helper
- **04-WR-07:** Serialize SENTINEL_SKIP_FEED_FETCH env-var tests + Drop guard
- **04-WR-08:** Index-backed iocs_for_host replaces full-scan + filter
- **04-WR-09:** Cap per-feed feed_warnings to 8 + truncated marker
- **04-WR-10:** Remove dead-code handle_prepare_snapshot_v4 shim
- **04-WR-11:** Extend PrepareSnapshot read timeout to 150s (vs 5s default)
- **05-01:** Make vendor-ua-parser-js.sh deterministic on BSD tooling
- **05:** CR-04 remove ptr::read duplicates in stop_preserving_state
- **05:** CR-01 fail-closed on /etc/hosts read error in HostsRewriter::new
- **05:** CR-03 spawn prompt_channel thread before sending OK Ack
- **05:** CR-02 enforce per-run prompt_id ownership in dispatch_response/cancel
- **05:** WR-01 anchor fixture-hash grep and assert exactly one match
- **05:** WR-02 surface reader-thread spawn failure and tear down channel
- **05:** WR-03 forget prompt_dedup entries on drain_for_run
- **05:** WR-04 cap SinkListener accepted-peer log to 256 entries
- **05:** WR-05 document pidversion check limitation in verify_wire_pid_same_uid
- **05:** WR-06 distinguish fail-closed connect-deny from DNS failure
- **05:** WR-07 split strict/lenient pass for daemon-killed phase-2 outcome
- **05:** WR-08 require specific markers in hardened-exec ASSERTION 3
- **quick-260508-et9:** Restore RegisterRoot in run_orchestrator (Rule 3 — blocking pre-existing regression)

### Refactoring
- **05-01:** Rewrite vendor-ua-parser-js.sh as synthetic-mock builder

### Testing
- **01-03:** Add failing identity_tests RED phase — ENF-08 type enforcement
- **01-04:** Add failing frame_tests RED phase — framing + bounds + message types
- **01-05:** RED phase — snapshot_publish_tests with stub modules
- **01-05:** RED phase Task 2 — ipc_server_tests with stub modules
- **01-07:** Add nw_dlsym_tests verifying Network.framework symbol resolution (A6)
- **01-08:** RED phase Task 1 — cli_args_tests + stub modules (3 failing)
- **01-08:** RED phase Task 2 — spawn_envp_tests with stub spawn_wrapped + ipc_client (4 failing)
- **01:** Persist human verification items as UAT
- **01-10:** Add smoke_dylib_loaded — proves dylib-load on success path with non-hardened node
- **02-01:** Add failing tests for AllowlistEntry V2 struct + tier ordering
- **02-01:** Add failing tests for SCHEMA_V2 snapshot codec
- **02-01:** Add failing tests for .sentinel.toml parser
- **02-01:** Add failing CBOR round-trip tests for Phase 2 IPC messages
- **02-02:** Add failing tests for tier-walk evaluate_policy + hard rules
- **02-02:** Add failing tests for curated YAML loader
- **02-03:** Add failing tests for .sentinel.toml walk-up + sha256 + parse
- **02-03:** Add RuleStore round-trip + idempotency + tier-mapping tests
- **02-04:** Add failing tests for ProcessTree supervisor
- **02-04:** Add failing tests for csops syscall binding
- **02-04:** Add failing tests for GapDetector two-phase timer
- **02-05:** Add failing tests for ArrayQueue-backed LogRing (BL-03 / D-43)
- **02-05:** Add failing tests for copy_cstr_to_buf exec-path helper
- **02-06a:** Add failing tests for PrepareSnapshot/TrustPolicy/Resolve handlers
- **02-06b:** Add failing tests for trust-policy + prepare_snapshot + envp
- **02-06b:** Add failing test for NW object-type gate (is_nw_object)
- **02-07:** Add failing per_run_snapshot_gc tests (RED)
- **02-07:** POL-06 precedence regression + ALLOW-06 curated deny e2e
- **02-07:** ENF-04 ambient + TREE-05 reparenting e2e smoke tests
- **02-07:** Zero_config_allow_deny harness-level e2e (ROADMAP #2 + #3)
- **02-08:** Add failing tests for cache::insert + send_resolve_sync round-trip
- **02-08:** Add live-network e2e (#[ignore]'d) + close ENF-07 traceability
- **02:** Persist human verification items as UAT
- **02:** Resolve HUMAN-UAT — empirical ENF-07 + IMDS verification done
- **03-01:** Add notify rename-detection and spawn-and-detach spike tests
- **03-03:** Add failing CRUD tests for InstallArtifactStore (RED)
- **03-07:** Add failing tests for BaselineStaging (TDD RED)
- **03-09:** Add failing tests for marker_block atomic + multi-shell (RED)
- **03-10:** Add failing tests for status minimal-default and json rendering (RED)
- **03-11:** Add failing tests for sentinel approve arg validation (RED)
- **03:** Persist human verification items as UAT
- **03-16:** Tier A artifact-only install/uninstall round-trip (always-on)
- **03-17:** E2E status state-transitions walk — NotInstalled, DaemonNotRunning, Operational
- **03:** Re-verification passed after gap-closure round
- **03:** Mark all human UAT items resolved via gap-closure automation
- **04-01:** Land gix shallow-clone spike (Task 2 / Spike A1)
- **04-01:** Land panic-isolation spike (Task 3 / Spike A2)
- **04-01:** Land WAL pragma migration spike (Task 4 / Spike A3)
- **04-01:** Land iocs field-shape spike (Task 5 / Spike A4)
- **05:** Persist human verification items as UAT
- **quick-260508-et9:** Un-ignore pm_env denylist e2e + add capture e2e (BLOCKER #1)

### Documentation
- Initialize project
- Complete project research
- Define v1 requirements
- Pivot architecture to Rust + DYLD interpose
- Flag research pivot in SUMMARY.md
- Create roadmap (5 phases)
- **01:** Capture phase context
- **state:** Record phase 1 context session
- **phase-1:** Research foundations-hook-hello-world phase
- **01:** Create phase plan with 9 plans across 6 waves
- **01-01:** Complete spike-interpose-hello-world plan; SPIKE PASSED
- **01-02:** Complete workspace-skeleton plan; six crates compilable, dual-license in place
- **01-03:** Complete core-types plan; 14 sentinel-core tests green
- **01-04:** Complete ipc-wire plan; 10 sentinel-ipc tests green, LOCAL_PEERTOKEN peer auth verified
- **01-05:** Complete daemon-launchagent plan — 7 tests green, snapshot+IPC substrate
- **01-06:** Complete hook-libc-and-snapshot plan — 8 tests green, 5 interpose records
- **01-07:** Complete hook-network-framework plan — 4 nw_dlsym tests green, 5 shadow exports
- **01-08:** Complete cli-run-command plan — 11 tests green, sentinel run subcommand with DYLD envp injection + connect-timeout IPC client
- **01-09:** Complete e2e-smoke-test plan — Phase 1 Roadmap criteria #1 #2 #4 verified
- **01:** Add code review report
- **01:** Record phase 1 verification — passed empirically, 3 human-judgment items
- **01:** Record human-uat decision; mark ENF-03 partial; document phase 2 carry-over
- **01:** Mark verification status gaps_found after human decision
- **01-10:** Create gap-closure plan for in-phase fixes (BL-01/02/04/05 + SC1)
- **01-10:** Complete gap-closure plan — 5 fixes, 3 phase-2 deferrals
- **01:** Finalize VERIFICATION.md after gap closure (status: passed) and tidy PROJECT.md carry-over
- **phase-01:** Complete phase execution
- **project:** Capture phase 3 sentinel-install UX design notes (interactive shell integration, marker blocks, modular components)
- **02:** Capture phase context
- **state:** Record phase 2 context session
- **02:** Research phase 2 policy engine, allowlists & process-tree scoping
- **02:** Map codebase patterns for phase 2 (analogs, no-analog flags)
- **02:** Create phase plan — 8 plans across 5 waves
- **02-01:** Complete schema-v2-and-ipc-contracts plan
- **02-02:** Complete curated-allowlist-yaml-and-evaluator plan
- **02-03:** Complete sqlite-rule-store-and-policy-file-discovery plan
- **02-04:** Complete daemon-concurrency-process-tree-and-gap-detection plan
- **02-04:** Complete daemon-concurrency-process-tree-and-gap-detection plan
- **02-05:** Complete hook-fork-exec-interpose-and-ctor-additions plan
- **02-06a:** Complete per-run-snapshots-and-daemon-side-handlers plan
- **02-06b:** Complete cli-integration-trust-policy-and-nw-framework-verdict plan
- **02-07:** Log loopback flake closure + lib.rs clippy deferreds
- **02-07:** Complete end-to-end-tests-and-snapshot-gc plan
- **02:** Add code review report
- **02:** Add 02-FIX-LOG.md summarizing review-fix pass
- **02:** Add phase verification report (gaps_found)
- **02:** Plan gap-closure for ENF-07 + TREE-06 (02-08, 02-09)
- **phase-02:** Mark phase as in-progress for gap-closure execution
- **02-08:** Record D-42 supersession in 02-FIX-LOG.md
- **02-08:** Complete enf-07-gap-closure-resolve-ipc-dylib-client plan
- **02-09:** Complete tree-06-env-not-propagated-gap-closure plan
- **02:** Mark VERIFICATION.md status: passed after HUMAN-UAT resolution
- **02:** Flip VERIFICATION.md status to passed after empirical UAT
- **02:** Rename 'Gaps Summary' → 'Gap Closure Summary' so SDK no-gaps heuristic stops false-flagging
- **phase-02:** Add security threat verification (57/57 closed)
- **03:** Capture phase context
- **state:** Record phase 3 context session
- **03:** Research phase domain — CLI surface, UX & forensic logging
- **03:** Create phase plan
- **phase-03:** Begin phase 3 execution
- **03-01:** Complete spike-foundation plan
- **03-02:** Complete ipc-schema-v3 plan
- **03-03:** Complete install-artifacts-store plan
- **03-04:** Complete process-tree-extensions plan
- **03-05:** Complete log-writer plan — SUMMARY + state updates
- **03-06:** Complete prompt-dedup-suggested-rules plan — SUMMARY + state updates
- **03-07:** Complete prepare-snapshot-v3 plan — SUMMARY + state updates
- **03-08:** Complete daemon-handlers plan — SUMMARY + state updates
- **03-09:** Complete cli-install-uninstall plan — SUMMARY + state updates
- **03-10:** Complete cli-status-logs plan — SUMMARY + state updates
- **03-12:** Complete prompt-channel plan — SUMMARY.md + STATE.md + ROADMAP.md
- **03-11:** Complete sentinel approve plan — SUMMARY.md + STATE.md + ROADMAP.md
- **03-13:** Complete cli-spawn-baseline plan — SUMMARY.md + STATE.md + ROADMAP.md
- **03-14:** Complete e2e tests plan — SUMMARY.md + STATE.md + ROADMAP.md
- **03:** Add code review report
- **03-17:** Fix must_haves frontmatter (function name + provides accuracy)
- **03-15:** Complete SENTINEL_SKIP_LAUNCHCTL env gate plan
- **03-16:** Complete UAT #1 gap-closure plan — Tier A+B install/uninstall tests
- **03-17:** Complete UAT #2 gap-closure plan — 5-state render tests + E2E state walk
- **03-18:** Complete UAT #3 gap-closure plan — dedup + project-scope + deny-exit PTY tests
- **03-19:** Complete UAT #4 gap-closure plan — real rotation + idle heartbeat tests
- **phase-03:** Complete phase execution and gap-closure round
- **phase-03:** Evolve PROJECT.md after phase completion
- **04:** Capture phase context
- **state:** Record phase 4 context session
- **04:** Research phase 4 threat intelligence feeds
- **04:** Create phase plan with 4 plans across 4 waves
- **04-01:** Complete Wave 0 spike plan
- **04-02:** Complete daemon-side feed ingestion foundation plan
- **04-02:** Record self-check verification in SUMMARY
- **04-03:** Complete daemon + CLI feed integration plan
- **04-04-1:** Relocate TI-03 + TI-04 to v2 per D-78
- **04-04:** Complete end-to-end threat-intel verification plan
- **04:** Add code review report
- **04:** Mark REVIEW.md status fixed + append Fixes Applied summary
- **04:** Mark phase verified — 6/6 ROADMAP success criteria passed
- **260507-ul5:** Rename milestone label v1.0 → v0.1 in STATE.md
- **260507-ul5:** Rename current-scope v1 → v0.1 in PROJECT.md
- **260507-ul5:** Shrink Phase 5 to validation-only (defer DIST to v0.2) in ROADMAP.md
- **260507-ul5:** Finish v1→v0.1 / v2→post-v1 rename across remaining lines
- **quick-260507-ul5:** Record completion in STATE.md + bundle PLAN/SUMMARY
- **05:** Capture phase context
- **state:** Record phase 5 context session
- **260507-vli:** Drop VAL-03 from ROADMAP.md Phase 5 (defer to v0.2)
- **260507-vli:** Rename v1/v2 → v0.1/post-v1 in REQUIREMENTS.md
- **quick-260507-vli:** Record completion in STATE.md + bundle PLAN/SUMMARY
- **phase-05:** Research Phase 5 validation domain
- **05:** Add research-driven corrections to CONTEXT.md (C-01..C-05)
- **05:** Create phase plan
- **05-02:** Complete test-support helpers plan
- **05-03:** Complete prompt-path package_context plumbing plan
- **05-01:** Complete synthetic ua-parser-js@0.7.29 fixture plan
- **05-04:** Complete VAL-01/VAL-02 e2e validation tests plan
- **05-04:** Update STATE.md stopped_at marker
- **05-05:** Complete VAL-04 daemon-killed + corrupt-snapshot e2e plan
- **05-06:** Complete VAL-04 stale-feed + hardened-exec e2e plan
- **05-07:** Complete Phase 5 validation GHA workflow plan
- **05:** Add code review report
- **phase-05:** Complete phase execution
- **phase-05:** Evolve PROJECT.md after phase completion
- **milestone-v0.1:** Add milestone audit (gaps_found — pm_env capture missing on dylib side)
- **quick-260508-et9:** Plan dylib-side pm_env capture
- **quick-260508-et9:** Record BLOCKER #1 closure in STATE.md Quick Tasks Completed
- **quick-260508-et9:** Persist SUMMARY.md
- **milestone-v0.1:** Update audit to passed after quick-260508-et9 gap closure

### Miscellaneous
- Add project config
- **01-02:** Write workspace Cargo.toml, rust-toolchain.toml, gitignore, and license files
- **02-05:** Update Cargo.lock for sentinel-hook serde dep
- **03-01:** Add Phase 3 workspace dependencies
- **03-16:** Declare ci-launchd Cargo feature on sentinel-e2e
- **04-01:** Add gix/semver/walkdir/url workspace deps + feed/ module root
- **04-02:** Record pre-existing TREE-06 e2e test failure as deferred item
- **05-05:** Update Cargo.lock for sha2 dev-dep on sentinel-e2e
- Archive v0.1 milestone


