# Linux Support V2 Implementation Spec

Issue: [Linux support (v2)](https://github.com/stentorian-io/guard/issues/2)

## Reader And Action

This spec is for an internal Stentorian Guard engineer planning the Linux port.
After reading it, they should be able to choose the first implementation slice,
estimate the remaining work, and identify which macOS guarantees do not have a
Linux equivalent.

## Current State

Stentorian Guard is still macOS-first. The repository compiles selected crates
on Linux, but that is a portability gate, not product support. Non-macOS OS
capabilities mostly return explicit unsupported errors or conservative stubs.

The issue body still uses old Sentinel names and proposes a new platform crate.
The current codebase already has an OS boundary in `guard-os`, so the port
should extend that boundary instead of creating another top-level platform
abstraction unless the existing crate becomes demonstrably too broad.

The v2 port is possible, but not as a simple flag flip. LD_PRELOAD makes the
basic hook loading path easier than DYLD, while process identity, peer
authentication, binary trust, hardware-backed signing, and daemon lifecycle all
need Linux-specific designs.

## Recommendation

Use `guard-os` as the platform boundary and move Linux support through small
vertical slices:

1. Make platform constants and artifact names selectable.
2. Add Linux path resolution and local daemon lifecycle in development mode.
3. Add Linux process and peer identity based on kernel credentials plus procfs.
4. Build the hook as an ELF shared object and prove LD_PRELOAD network
   interposition end to end.
5. Replace macOS hardened-runtime classification with Linux setuid, setgid, file
   capability, ELF, and syscall-instruction classification.
6. Keep Linux development mode explicit, and decide the production signing and
   install model before claiming supported consumer installs.

Do not declare Linux support until a Linux e2e suite proves wrapped commands
fail closed for denied outbound connections and known hook-bypass classes.

## Platform Boundary

### Keep

Keep `guard-os` as the owner of direct OS calls:

- Peer identity for Unix sockets.
- Process identity and pid-reuse checks.
- Binary classification facts.
- Platform path defaults.
- Service lifecycle helpers where they are OS-specific.

Keep policy evaluation, snapshot verification, IPC frame encoding, rule storage,
prompting, and status rendering platform-neutral.

### Change

The current shared identity type is named around macOS audit tokens. Linux can
preserve the wire shape temporarily, but the domain model should stop implying
that every verified identity is an audit token.

Recommended shape:

```rust
enum PlatformProcessIdentity {
    MacosAuditToken(AuditToken),
    LinuxProcfs {
        pid: u32,
        uid: u32,
        gid: u32,
        starttime_ticks: u64,
        exe_inode: Option<u64>,
        exe_device: Option<u64>,
    },
}
```

For compatibility, the existing IPC schema can continue carrying a legacy token
while Linux is experimental, with a new schema version added when daemon logic
needs the richer Linux fields.

## Subsystem Plan

### 1. Platform Constants, Paths, And Artifact Names

What needs changing:

- The central path module has macOS system paths, log paths, hook names, service
  names, and DYLD environment names baked in.
- The CLI locates only a `.dylib` hook and production install path.
- The hook and tests scrub and inspect DYLD-specific variables.

Linux design:

- Use `LD_PRELOAD` as the injection variable.
- Build and install `stt-guard-hook.so`.
- Use XDG locations for user-mode development state.
- For production installs, choose between a system install under `/usr/local`
  with a dedicated service user and a user service under systemd. The current
  macOS security model favors system-owned artifacts; Linux should not weaken
  that by defaulting to user-writable production binaries.

Possible:

- XDG development paths are straightforward.
- Platform-specific hook artifact naming is straightforward.

Not possible without a product decision:

- A final production path and ownership model, because it depends on whether
  Linux v2 keeps the hardened root-owned install requirement.

First slice:

- Add platform-specific constants for injection environment variable and hook
  filename.
- Keep the existing macOS values unchanged.
- Add tests that the CLI strips and sets the right variable per target OS.

### 2. LD_PRELOAD Hook Loading

What needs changing:

- The CLI spawn path prepends `DYLD_INSERT_LIBRARIES`.
- The hook uses Mach-O interpose records and a DYLD self-test.
- Network.framework replacement is macOS-only and should not load on Linux.

Linux design:

- Export the same libc symbol names from the ELF shared object.
- Use `dlsym(RTLD_NEXT, ...)` for real function pointers on Linux.
- Keep raw syscall call-through where it is already required for robustness, but
  do not assume the macOS DYLD recursion behavior applies on Linux.
- Gate Mach-O interpose records and Network.framework code to macOS.
- Add a Linux self-test that verifies the exported replacement symbols are
  active under LD_PRELOAD.

Possible:

- Interposing `connect`, `send`, `sendto`, `sendmsg`, `getaddrinfo`, `execve`,
  `execv`, `execvp`, `fork`, `vfork`, `posix_spawn`, and `posix_spawnp`.
- Reusing most snapshot load and policy evaluation code.

Not possible:

- Interposing static binaries or privileged execs where the dynamic loader
  strips LD_PRELOAD.
- Covering raw syscall instructions without the separate layered enforcement
  work tracked by issue #1.

First slice:

- Build the hook on Linux as a `.so`.
- Add a Linux smoke e2e that sets a marker from the constructor under
  LD_PRELOAD.
- Then add a deny e2e for a simple dynamically linked network client.

### 3. Raw Syscall ABI

What needs changing:

- The current raw syscall wrapper is XNU-specific.
- Syscall numbers, register conventions, and error conventions differ on Linux.

Linux design:

- Split raw syscall implementation by OS and architecture.
- Support x86_64 and aarch64 first.
- Use Linux syscall numbers from libc where available, or define constants in a
  small Linux-only module when libc does not expose them.
- Convert negative Linux syscall returns into libc-compatible errno behavior for
  replacement functions.

Possible:

- Direct wrappers for read, write, writev, open/openat, connect, send/sendto,
  sendmsg, fork/vfork, execve, and getsockopt on x86_64 and aarch64.

Not possible:

- A single syscall table shared with macOS.
- Reliable Linux support for every architecture without architecture-specific
  wrappers and CI coverage.

First slice:

- Add Linux wrappers only for the calls needed by the first LD_PRELOAD network
  e2e.
- Extend as exec and classification slices need more calls.

### 4. Peer Authentication

What needs changing:

- The daemon authenticates peers via macOS kernel audit tokens.
- Management authorization and process tracking currently assume audit-token
  identity.

Linux design:

- Use `SO_PEERCRED` to obtain kernel-sourced pid, uid, and gid for a connected
  Unix socket.
- Immediately read procfs start time for the peer pid as a pid-reuse guard.
- Read the peer executable path and inode when available.
- Treat procfs data as supplemental identity, not as equal strength to macOS
  audit tokens.

Possible:

- Strong enough peer identity for unprivileged Unix socket clients when checked
  immediately and paired with daemon-side authorization.
- PID-reuse mitigation using starttime.

Not possible:

- A Linux equivalent of macOS pidversion or Security.framework guest lookup.
- Race-free process identity from procfs alone.

Security delta:

Linux peer auth is weaker. The daemon must document the TOCTOU window between
`SO_PEERCRED` and procfs reads. Mutating operations should continue requiring
signed management payloads, so peer identity is not the only authorization
barrier.

First slice:

- Add a Linux peer identity implementation in `guard-os`.
- Keep non-Linux behavior unchanged.
- Add unit tests using a Unix socket pair and a real child process.

### 5. Process Tracking

What needs changing:

- The process tree is keyed by audit tokens.
- Fork and exec events are reported by the hook using audit-token-shaped fields.
- Gap detection uses pid and pidversion positions inside the token.

Linux design:

- Use pid plus procfs starttime as the stable process key.
- Treat hook-reported fork and exec events as advisory until the daemon verifies
  the sending peer and child identity through procfs.
- Evaluate Linux netlink proc connector as an optional supplement, not a v2.0
  requirement, because it may require elevated capabilities and is often limited
  in containers.

Possible:

- Process-tree tracking within wrapped, dynamically linked process subtrees.
- PID-reuse mitigation using starttime.
- Container-friendly operation without netlink by relying on hook reports.

Not possible:

- Complete process event visibility for unhooked or static child processes
  without ptrace, eBPF, netlink, seccomp user notifications, or another kernel
  mechanism.

First slice:

- Introduce an internal process-key abstraction.
- Keep macOS backed by audit token.
- Add Linux-backed process keys only where peer verification and fork/exec
  tracking need them.

### 6. Binary Classification And Exec Blocking

What needs changing:

- Exec blocking is based on Mach-O, code-signing flags, fat binaries, and
  hardened-runtime behavior.
- The structural scanner is Mach-O-specific.

Linux design:

- Replace hardened-runtime detection with Linux hook-shedding detection:
  setuid, setgid, and file capabilities.
- Parse ELF headers for architecture and executable segments.
- Scan executable segments for raw syscall instruction patterns.
- Classify static binaries as a coverage risk because LD_PRELOAD cannot
  interpose them.
- Treat file capabilities as privilege escalation risk because they alter the
  loader and process privilege model.

Possible:

- Blocking setuid and setgid exec targets before LD_PRELOAD is stripped.
- Blocking or warning on file-capability binaries.
- ELF scanning for syscall instructions on supported architectures.

Not possible:

- Linux code-signing parity with macOS. IMA/EVM may exist on some enterprise
  hosts, but it is not a general consumer guarantee.

First slice:

- Add a Linux ELF classifier with setuid and setgid checks.
- Then add file capability detection.
- Then port syscall-instruction scanning to ELF executable segments.

### 7. Hardware-Backed Signing

What needs changing:

- Production signing is implemented through macOS Secure Enclave and Keychain.
- The README already says Linux requires a hardware-backed signer such as FIDO2
  or TPM, but no provider exists yet.

Linux design:

- Keep the requirement that production signatures come from non-exportable keys.
- Choose one initial provider:
  - FIDO2/security key for user-presence signing.
  - TPM-backed P-256 key for machine-bound signing.
- Do not fall back to software keys in production.

Possible:

- Preserve the existing signature payload formats if the provider emits ECDSA
  P-256 signatures compatible with current verification.

Not possible:

- Calling Linux v2 production-ready while rule and snapshot signing still rely
  on test-signer or exportable software keys.

First slice:

- Define the provider interface and failure modes.
- Add Linux production commands only after a provider is chosen.

### 8. Daemon Lifecycle

What needs changing:

- Install and health checks are LaunchDaemon, dscl, root:wheel, and macOS path
  specific.
- The CLI help text describes LaunchDaemon setup.

Linux design:

- Development mode can spawn the daemon directly, as macOS already does.
- Production mode should use either a systemd system service with a dedicated
  service user, or a systemd user service with a clearly weaker security model.
- If the project keeps root-owned production artifacts, use a system service.

Possible:

- A systemd unit with restart-on-failure.
- Existing watchdog reuse, or later replacement with sd_notify.

Not possible:

- LaunchDaemon parity on non-systemd distros without separate init-system
  support.

First slice:

- Add XDG-based Linux development state/log paths.
- Start a sibling `stt-guard-daemon serve --state-dir ...` from the CLI when a
  Linux development daemon is not already reachable.
- Make `stt-guard init` on Linux fail closed with an explicit unsupported
  production-install message.
- Defer production install until signing and ownership decisions are settled.

## Containers And CI

Linux is a major CI and container use case, but containers reduce available
kernel features. The first supported Linux target should be glibc on Ubuntu
latest because the repository already uses Ubuntu runners.

Initial CI should add:

- Linux unit tests for `guard-os`.
- Linux hook build.
- Linux LD_PRELOAD smoke e2e.
- Linux deny e2e using a dynamically linked test harness.

Do not require netlink, privileged Docker, or host-level systemd for the first
CI proof. Those can be separate production-install validations later.

## Milestone Slices

### Slice A: Platform Constants

Goal: make the code stop spelling DYLD and `.dylib` where a platform choice is
required.

Verification:

- Existing macOS tests continue to pass.
- Linux compile gate remains green.

### Slice B: Linux Peer And Process Identity

Goal: make Linux daemon peer authentication return a verified identity based on
kernel credentials and procfs.

Verification:

- Linux `guard-os` unit tests cover socket peer credentials, starttime parsing,
  and executable identity reads.

### Slice C: Linux Hook Loads

Goal: prove `stt-guard-hook.so` constructor executes through LD_PRELOAD.

Verification:

- Linux e2e marker test passes.

### Slice D: Linux Network Deny

Goal: prove a wrapped dynamic Linux process cannot reach a default-denied
destination through libc networking.

Verification:

- Linux e2e denial test passes.
- Snapshot load failure still fails closed.

### Slice E: Linux Exec Gap Blocking

Goal: block known LD_PRELOAD shedding exec targets.

Verification:

- setuid and setgid harnesses are blocked before exec.
- file capability harness is classified according to the chosen policy.

### Slice F: Linux Development Daemon And Production Gate

Goal: make Linux usable for development without implying production support.
Production install remains blocked until root-owned artifact layout, systemd
service management, and hardware-backed signing decisions are made.

Verification:

- Linux uses XDG development state paths.
- Linux CLI can start a local sibling daemon for wrapped commands.
- `stt-guard init` on Linux reports that hardened production install is not
  implemented yet.

Future production verification:

- Privileged Linux install-health e2e passes in a controlled runner.

## Open Decisions

1. Should Linux v2 require glibc only for the first release, or include musl?
2. Should production Linux install use a systemd system service or allow a
   weaker user-service mode?
3. Which hardware-backed signer ships first: FIDO2/security key or TPM?
4. Are file capabilities always blocked, or can a trusted-runtime allowlist
   permit specific binaries?
5. Is netlink proc connector worth an optional feature despite capability and
   container limitations?
6. Should static ELF binaries be blocked by default inside wrapped trees?
7. What minimum Linux kernel and distro versions are supported?

## What Is Not In V2.0

The first Linux release should not promise system-wide enforcement, static
binary coverage, raw-syscall coverage, kernel-level sandboxing, or code-signing
parity with macOS.

Those are separate enforcement layers. The Linux v2.0 bar should be honest:
default-deny outbound network enforcement for dynamically linked wrapped
process trees, fail-closed snapshot handling, authenticated daemon IPC, and
explicit blocking of known LD_PRELOAD shedding paths.
