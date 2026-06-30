# AGENTS.md

This file defines how coding agents should work in this repository. Follow it
when reading, editing, testing, reviewing, or delegating work to subagents.

## Project Context

Stentorian Guard is a Rust 2024 workspace for macOS-first supply-chain defense.
It wraps developer commands, injects a hook library with
`DYLD_INSERT_LIBRARIES`, and enforces default-deny outbound networking through a
daemon, signed policy snapshots, IPC, and a fail-closed hot path.

Primary crates:

- `crates/guard-cli`: `stt-guard` command-line entry point.
- `crates/guard-daemon`: LaunchDaemon service, policy engine, persistence, and
  IPC handlers.
- `crates/guard-hook`: injected `cdylib` that interposes libc network and
  process APIs.
- `crates/guard-core`: domain types, policy evaluation, snapshots, and shared
  data.
- `crates/guard-ipc`: CBOR wire protocol and Unix socket transport.
- `crates/guard-os`: OS-specific helpers and system integration boundaries.
- `crates/guard-watchdog`: daemon liveness monitor.
- `crates/guard-e2e`: end-to-end tests and harness binaries.

Read `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` before changing behavior
that affects installation, privilege boundaries, hook loading, IPC, persistence,
or the security model.

## How To Work

- Read the existing implementation before adding abstractions or reshaping
  module boundaries.
- Make the smallest coherent change that solves the current task.
- Keep responsibilities cohesive: policy evaluation, IPC framing, persistence,
  OS integration, CLI presentation, and hook interposition should stay cleanly
  separated.
- Remove duplication only when repeated code represents the same concept and has
  the same reason to change.
- Add dependencies only with clear justification. Prefer the standard library or
  existing workspace dependencies when they fit.
- Preserve user changes. Never revert unrelated work.
- Ask only when an ambiguity materially affects security, public behavior, data
  safety, or compatibility.

## Readable Rust

Code should read well, almost like prose. A reader should infer what something
does and how it works from names, structure, and flow before needing comments.

### Names

- Name files, modules, types, functions, variables, tests, and helpers so their
  intent is clear without comments.
- Prefer domain-specific names over generic names: `prepare_snapshot`,
  `evaluate_policy`, `resolve_destination`, `verify_snapshot_signature`.
- Avoid vague names like `data`, `item`, `value`, `result`, `handle`, or
  `manager` when a domain term exists.
- Include state or uncertainty in the name when it affects behavior, such as
  `table_key_or_none`, `fields_or_none`, `snapshot_path`, or
  `verified_manifest`.
- Use repeated terms first when grouping related variables so related concepts
  scan together, such as `policy_decision_cached`,
  `policy_decision_resolved`, and `snapshot_manifest_verified`.
- Helper functions should name the decision or transformation they perform:
  `next_non_blacklisted_id`, `trusted_registry_rule_for_host`,
  `should_prompt_for_destination`.

### Comments

- Prefer renaming or restructuring code over adding explanatory comments.
- Comments should explain why something is surprising, fragile,
  platform-specific, security-sensitive, or intentionally non-obvious.
- Use comments for unsafe invariants, macOS/DYLD behavior, fail-closed
  reasoning, compatibility workarounds, intentional no-ops, performance-sensitive
  hot paths, and edge cases that future refactors might accidentally remove.
- Do not comment obvious code or use comments to compensate for poor names.

### Shape

- Let functions have a visible rhythm: gather inputs, validate, derive named
  values, perform the operation, return.
- Let code breathe with blank lines between distinct phases.
- Put an empty line above and below multi-line statement blocks, including
  multi-line `let` initializers, `if`/`match` blocks, unsafe blocks, and
  multi-line method chains. Do not let those blocks run directly into
  single-line statements.
- Separate adjacent control-flow blocks with a blank line when they are
  independent checks. Keep `if`/`else if`/`else` chains together because they
  represent one decision.
- Do not add blank lines between isolated one-line statements merely because
  they are unrelated; solo statements stay together.
- Use blank lines to separate a logical group from a solo statement, a solo
  statement from a following logical group, or one logical group from another
  group. A group is usually two or more related statements or a block.
- Separate a declaration from a following run of assignments with a blank line,
  such as `let mut val = ...;` followed by multiple `val[i] = ...;`
  statements. A single declaration plus one immediate assignment may stay
  together when they read as one small setup step.
- Put a blank line before a final return expression such as `Ok(info.pbi_gid)`
  when it follows validation, branching, or any multi-line block.
- Group related declarations together, especially when names share terms.
- Keep validation visually separate from mutation, I/O, or return construction.
- Prefer explicit branching when it makes the business rule clearer.
- Prefer `match` for meaningful domain variants and `if` for one local
  condition.
- Avoid deeply nested control flow; name intermediate decisions instead.
- Use `map`, `and_then`, and similar combinators only when they improve
  readability.

### Line Shape

- Formatting is automated, but code shape is still an authoring
  responsibility. Do not throw tangled code at the formatter and call it
  readable.
- If a line becomes wrapped, treat it as a signal to reconsider the shape: name
  an intermediate value, extract a meaningful helper, simplify the expression,
  or split conceptually distinct work.
- Keep work on one line when it is truly one thought and reads naturally.
- Use multi-line calls, signatures, struct literals, enum variants, and match
  arms when the pieces are conceptually important and the vertical structure
  improves scanning.

### Types And Data Flow

- Use `Option`, `Result`, enums, and newtypes to encode uncertainty, failure,
  and invariants.
- Prefer making invalid states unrepresentable over relying on comments or
  caller discipline.
- Prefer `Result<T, E>` with structured errors over stringly typed errors.
- Use `thiserror` for domain errors where it matches existing style.
- Avoid boolean parameters when an enum would make the call site clearer.
- Avoid `unwrap` and `expect` in production code unless the invariant is local,
  obvious, and unrecoverable. Tests may use them when they keep the test clear.
- Prefer borrowing over cloning. Clone only when ownership clarity or lifetime
  simplicity is worth it.
- Keep lifetimes boring. If explicit lifetimes become complex, reconsider the
  design.

## Security Expectations

- Treat this as security-sensitive software. A convenient fallback that weakens
  enforcement is usually a bug.
- Fail closed when working on enforcement paths, snapshot loading, IPC, signing,
  hook initialization, or policy resolution.
- Do not weaken root ownership, daemon isolation, signature checks, snapshot
  validation, peer authentication, or hardened-runtime handling without an
  explicit security rationale.
- Avoid ambient authority. Pass capabilities, paths, handles, and policy inputs
  explicitly where practical.
- Keep unsafe blocks tiny and document the invariant that makes them sound.
- Keep hook hot-path allocations, locks, syscalls, and IPC calls intentional,
  measured, explicit, and predictable. Cache-hit paths should remain fast.
- Do not hide I/O, process execution, filesystem mutation, IPC, or network
  access behind innocent-looking helpers.
- Keep error messages actionable, but do not leak secrets, private key material,
  or sensitive local environment details.

## Tests And Verification

Repository checks are enforced by Git hooks, including pre-commit, pre-push, and
commit-msg hooks. Do not run the same broad checks manually and then immediately
trigger them again through Git.

- During iteration, run only the narrowest meaningful test: the specific test
  case you wrote, the failing test you are debugging, or the smallest crate-level
  test that exercises the changed behavior.
- Let commit and push hooks run their configured broader checks.
- Run E2E tests when changing hook behavior, daemon behavior, IPC, install
  health, process tracking, policy resolution, or hardened-runtime handling and
  the hook suite does not already cover the confidence needed.
- Treat `scripts/ci-local.sh` as an explicit full-parity check, not a routine
  inner-loop command. It may perform privileged validation and mutate system
  install locations.
- Test behavior, not implementation details. Test names should describe the rule
  being protected, such as `denies_network_when_snapshot_signature_is_invalid`.
- Keep arrange, act, and assert phases visually separated with blank lines.
- If a required verification command cannot be run, report exactly why and what
  risk remains.

## Change Hygiene

- Do not mix broad refactors with behavioral changes unless the refactor is
  necessary to make the behavior safe.
- Do not commit or push after every small edit. Batch related changes into
  coherent commits, then push once the branch is ready for review or handoff.
- Keep generated artifacts, local build outputs, secrets, local machine paths,
  generated private keys, and production data out of commits.
- Update `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, or `docs/` when behavior,
  installation, threat model, commands, or operational expectations change.
- Use conventional commit style when committing:
  `feat: ...`, `fix: ...`, `test: ...`, `docs: ...`. Do not add a
  component/scope such as `fix(daemon): ...`; the commit-msg hook rejects
  scoped subjects.

## Agent And Subagent Expectations

- Subagents must follow this file too. When delegating, include the relevant
  crate, boundary, and verification expectations in the handoff.
- Prefer evidence over assertion. Before saying a change is complete, run the
  relevant verification or state why it was not run.
- Summaries should name the files changed, the behavior affected, and the
  commands executed.
- When reviewing code, lead with bugs, security risks, regressions, and missing
  tests before summarizing style or architecture concerns.
