# Compatibility Tracking

Stentorian Guard depends on platform behavior that can drift outside this
repository: macOS DYLD and hardened-runtime behavior, CPU architecture names,
Rust and LLVM target support, Xcode releases, installer packaging, reviewed
scanner behavior, and future Linux support expansion. The checked-in source of
truth is
[`compatibility-matrix.yaml`](../compatibility-matrix.yaml).

The manifest records the OS, CPU, syscall-pattern, and toolchain entries that
maintainers have already reviewed. The manifest does not grant runtime support
by itself; it keeps scanner coverage issue
[#1](https://github.com/stentorian-io/guard/issues/1) and Linux coverage issue
[#2](https://github.com/stentorian-io/guard/issues/2) connected to upstream
platform changes.

For platform-specific support decisions, see:

- [macOS support](macos.md)
- [Linux support](linux.md)
- [Windows support](windows.md)

## Compatibility Matrix

The tables below summarize the reviewed entries in the compatibility manifest.
They are intentionally explicit about status: tracked entries are visible to the
automation, but they are not automatically supported or trusted.

### OS, CPU, And Scanner Checks

| Surface | Reviewed entries | Status | Notes |
| --- | --- | --- | --- |
| macOS | 13 Ventura, 14 Sonoma, 15 Sequoia, 26 Tahoe | Supported | Primary macOS support set. |
| macOS | 12 Monterey | Best effort | Kept visible for compatibility drift. |
| macOS | 11 Big Sur | Historical tracking | Not a current support target. |
| Linux runtime path | Ubuntu, `glibc`, `x86_64` | Development-only smoke validation | Production systemd install design is tracked in issue [#70](https://github.com/stentorian-io/guard/issues/70), but activation is still blocked on hardware-backed signing and validation. |
| Linux kernel series | 7.0, 6.18, 6.19, 6.17, 6.16, 6.15, 6.14, 6.13, 6.12, 6.6, 6.1, 5.15, 5.10 | Tracked, not validated | Used to keep Linux planning connected to upstream drift. |
| Linux libc and architecture | `aarch64`, `musl` | Tracked, not validated | Linux coverage issue tracks validation work. |
| Windows | None | Not planned | No supported Windows enforcement path. |
| CPU architecture | `arm64`/`aarch64`, `x86_64` | Supported | Scanner behavior is covered for current support claims. |
| CPU architecture | `arm64e` | Tracked | Requires scanner review before support claims change. |
| CPU architecture | `arm64_32`, `x86`/`i386`, `arm32`, `powerpc`/`ppc`/`ppc64` | Historical tracking | Kept visible so scanner handling stays explicit. |
| CPU architecture | `riscv64`/`riscv32`, `loongarch64` | Tracked for Linux | Not a production support claim. |
| Syscall and exec scanning | libc connect family | Covered | Standard libc networking calls are interposed. |
| Syscall and exec scanning | raw syscall instructions, hardened-runtime DYLD strip | Tracked, fail closed | Coverage gaps do not silently become allowed. |
| Syscall and exec scanning | Linux ELF exec scanner | Unsupported, fail closed | Linux scanner support is tracked separately. |
| Syscall and exec scanning | unknown executable classification | Covered on macOS | Unknown or malformed non-script exec targets fail closed. |

### Toolchains And Packaging

| Surface | Reviewed entries | Status | Notes |
| --- | --- | --- | --- |
| Rust | 1.96.0 pinned, 1.85.0 minimum, stable channel | Reviewed | CI validates the checked-in support claim. |
| Rust targets | `aarch64-apple-darwin`, `arm64e-apple-darwin`, `i686-apple-darwin`, `x86_64-apple-darwin`, `x86_64h-apple-darwin` | Tracked | macOS target drift opens review work. |
| Rust targets | `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, `i686-unknown-linux-gnu`, `i686-unknown-linux-musl`, `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` | Tracked | Linux target drift opens review work. |
| Xcode | 15, 16, 26 | Reviewed | Upstream release drift opens review issues. |
| LLVM | 18, 19, 20, 21, 22 | Reviewed | Upstream release drift opens review issues. |
| Homebrew | `rust` 1.96.0, `llvm` 22.1.6 | Reviewed | Used by packaging and release automation. |

### Automation Boundaries

| Surface | Automation | Review boundary |
| --- | --- | --- |
| Platform and toolchain compatibility | Weekly scans compare upstream release sources with the reviewed compatibility matrix. | New entries open review issues. The matrix changes only through normal PR review. |
| Threat-intel deny rules | Nightly OSV.dev feed updates open PRs when new malicious-package IOCs are found. | Deny-rule changes land through PR review before being baked into a release. |
| Curated allow rules | Registry and CDN allowlists are versioned with the codebase and visible through status commands. | Adding or changing an allow rule requires review because it expands what protected processes may reach. |

## Weekly Tracker

`.github/workflows/compatibility-tracker.yml` runs every Monday at 08:00 UTC.
It executes:

```sh
scripts/compatibility-tracker.sh --create-issues
```

The tracker fetches the sources listed in the manifest, compares discovered
entries against reviewed entries, and opens review issues when it sees something
new. It intentionally does not commit or open pull requests for manifest
updates. A maintainer should review each issue, decide whether scanner coverage,
CI validation, docs, or Linux planning needs follow-up, and then update the
manifest in a normal PR.

Expected labels include `compatibility`, `cpu-arch`, `scanner-review`, `macos`,
`toolchain`, `lifecycle`, and `linux`.

## CI Validation

`.github/workflows/ci.yml` validates the checked-in compatibility manifest and
the platform matrix the project currently claims to support. The compatibility
tracker opens review issues when upstream sources drift; CI is the single place
that proves reviewed support still builds and tests.

Linux entries represent Ubuntu `glibc` `x86_64` smoke coverage plus tracked
review work for `aarch64`, `musl`, and kernel series. The production Linux
install layout is defined as a systemd-managed root-owned deployment under
`/usr/local/libexec/stt-guard`, `/var/lib/stt-guard`, and `/var/log/stt-guard`,
but it is not activated until hardware-backed signer enrollment and install
health validation are complete. Linux ELF exec-target scanning is compiled as an
explicit unsupported fail-closed boundary until ELF classification is
implemented. Privileged system mutation stays in the existing CI/E2E path where
it is explicit.

## Local Use

Validate the manifest without network access:

```sh
scripts/compatibility-tracker.sh --offline
```

Run a local scan without creating issues:

```sh
scripts/compatibility-tracker.sh
```

Create issues in a specific repository when authenticated with `gh`:

```sh
scripts/compatibility-tracker.sh --create-issues --repo stentorian-io/guard
```

The scan exits with status `2` when new review entries are detected. That is
expected in dry-run mode and lets automation distinguish "new review work" from
"script failed".
