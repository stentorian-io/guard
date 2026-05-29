# Linux Support

Linux has development-only initial support for wrapped `glibc` processes through
`LD_PRELOAD`. The currently validated Linux path is Ubuntu `glibc` `x86_64`
smoke coverage. Hardened production install, service management, complete
dynamically linked enforcement, and production hardware-backed signing are not
complete yet.

## Status

| Area | Status |
| --- | --- |
| Runtime support | Development-only initial support |
| Validated distribution/libc | Ubuntu `glibc` smoke coverage |
| Validated architecture | `x86_64` smoke coverage |
| Tracked libc coverage | `musl` |
| Tracked architecture coverage | `aarch64` |
| Enforcement implementation | `LD_PRELOAD` for wrapped dynamically linked processes; not complete dynamically linked enforcement |
| Production signer | Not implemented yet |
| Production install tracker | [#70](https://github.com/stentorian-io/guard/issues/70) |
| Runtime coverage tracker | [#2](https://github.com/stentorian-io/guard/issues/2) |

Tracked CPU architectures are `x86_64` and `aarch64`, but only Ubuntu `glibc`
`x86_64` smoke coverage is validated today.

The development runtime path covers wrapped dynamically linked processes where
the guard hook can be loaded through `LD_PRELOAD`. That does not imply complete
enforcement for all dynamically linked Linux programs.

Tracked kernel series currently include `5.10`, `5.15`, `6.1`, `6.6`, `6.12`,
`6.13`, `6.14`, `6.15`, `6.16`, `6.17`, `6.18`, `6.19`, and `7.0`. These
entries keep lifecycle review visible; they do not mean every kernel/libc
combination has been validated.

## Enforcement Model

The current Linux enforcement path uses `LD_PRELOAD` to load the guard hook into
wrapped processes. Current smoke coverage includes fail-closed connect behavior
and setuid/setgid `execve` blocking.

The exec-time scanner does not yet provide supported ELF classification. Linux
ELF child execs fail closed with an explicit unsupported-ELF reason instead of
being treated as clean or validated runtime coverage. Unknown non-script child
execs also fail closed. Linux builds compile an explicit ELF/LD_PRELOAD scanner
boundary for that unsupported state; they do not reuse macOS Mach-O
classification.

Peer identity is implemented for same-namespace Linux peers using
`SO_PEERCRED` and procfs. Namespace and container semantics remain tracked
compatibility work, not validated support.

`LD_PRELOAD` alone is not a complete long-term enforcement boundary. It can
cover ordinary dynamically linked user-space entry points, but static binaries,
direct syscalls, privileged transitions, and programs that intentionally bypass
the dynamic loader remain design-sensitive cases.

Linux support must preserve the same high-level rule as macOS support: unknown or
unverified network access fails closed.

## Production Install Design

The supported Linux production target is a systemd-managed system install on a
clean Ubuntu `glibc` `x86_64` host. The layout is intentionally close to the
macOS hardened install model:

| Component | Path | Owner and mode |
| --- | --- | --- |
| CLI, daemon, watchdog | `/usr/local/libexec/stt-guard/` | `root:root` directory `0755`; executables `0755` |
| Hook library | `/usr/local/libexec/stt-guard/stt-guard-hook.so` | `root:root` `0644` |
| Trusted signer manifest | `/usr/local/libexec/stt-guard/trusted-rule-signers.tsv` | `root:root` `0644` |
| Runtime state, DB, snapshots, IPC socket | `/var/lib/stt-guard/` | `_stt_guard:_stt_guard` `0711` |
| Logs | `/var/log/stt-guard/` | `_stt_guard:_stt_guard` `0711` |
| Daemon service | `/etc/systemd/system/stt-guard-daemon.service` | `root:root` `0644` |

The service identity is `_stt_guard` with home `/var/lib/stt-guard` and shell
`/usr/sbin/nologin`. The daemon unit runs
`/usr/local/libexec/stt-guard/stt-guard-daemon serve --state-dir
/var/lib/stt-guard` as that service identity, restarts on failure, and restricts
writes to the state and log directories with `ProtectSystem=strict`.

Linux production activation is still blocked on hardware-backed signer
enrollment. A production install must have a non-exportable signing key backed
by a Linux platform facility such as a security key or TPM-backed key before the
CLI can enable the systemd install path. Software-only private keys are not a
supported substitute.

If the default state directory resolves to `/var/lib/stt-guard`, the CLI treats
the host as a system install candidate and requires the hardened install health
gate. It must not auto-start a development daemon against the system state
directory.

## Install Health Failure Modes

Linux install health is fail-closed. `wrap`, `status`, and other protected
commands must refuse to proceed when any enforcement-critical artifact is
missing or malformed, including:

- missing `_stt_guard` service identity, wrong UID/GID mapping, login shell, or
  unexpected home directory
- missing daemon, watchdog, CLI, hook library, trusted signer manifest, state
  directory, log directory, or systemd unit
- non-root ownership or writable modes on binaries, hook library, trusted signer
  manifest, or the systemd unit
- state or log directories not owned by `_stt_guard`
- a systemd unit whose content differs from the reviewed definition
- missing, invalid, or untrusted hardware-backed signer enrollment
- invalid or missing policy snapshot material

Unsupported ELF child exec classification remains a runtime fail-closed
condition until production ELF classification is implemented.

## Compatibility Assumptions

The Linux port needs explicit answers for:

- namespace and container behavior for peer process identity and parent-child
  tracking
- direct syscall coverage
- static binary behavior
- dynamic loader behavior across `glibc` and `musl`
- CI behavior outside the current Ubuntu `glibc` `x86_64` smoke path
- hardware-backed signing support, likely through a FIDO2/security key or a
  TPM-backed key

The compatibility tracker follows kernel series, libc families, CPU
architectures, Rust targets, and LLVM target names so new platform drift becomes
review work instead of an implicit support expansion.

## Support Decisions

Linux support exists because the supply-chain threat model applies to CI
systems, build hosts, developer containers, and Linux workstations.

Linux is still marked development-only initial support because production
hardening work remains: service management, hardware-backed signer design,
distribution guidance, namespace/container validation, and coverage for bypasses
that are normal on Linux, including raw syscalls and static or specially loaded
binaries.

## What Would Change Support

Linux can move from development-only initial support to full support only after
the project has production install guidance, hardware-backed signing, and tests
that cover bypass-relevant cases for the selected distributions or kernel/libc
combinations.
