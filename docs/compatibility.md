# Compatibility Tracking

Stentorian Guard depends on platform behavior that can drift outside this
repository: macOS DYLD and hardened-runtime behavior, CPU architecture names,
Rust and LLVM target support, Xcode releases, Homebrew packaging, reviewed
runtime identities, and future Linux support expansion. The checked-in source of
truth is
[`compatibility-matrix.yaml`](../compatibility-matrix.yaml).

The manifest records the OS, CPU, syscall-pattern, and toolchain entries that
maintainers have already reviewed. Runtime integrity hashes are validated
against this same review ledger before they can be embedded in the hook. The
manifest does not grant runtime support by itself; it keeps scanner coverage issue
[#1](https://github.com/stentorian-io/guard/issues/1) and Linux coverage issue
[#2](https://github.com/stentorian-io/guard/issues/2) connected to upstream
platform changes.

For platform-specific support decisions, see:

- [macOS support](macos.md)
- [Linux support](linux.md)
- [Windows support](windows.md)

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
`toolchain`, `runtime`, `integrity`, `lifecycle`, and `linux`.

## CI Validation

`.github/workflows/ci.yml` validates the checked-in compatibility manifest and
the platform matrix the project currently claims to support. The compatibility
tracker opens review issues when upstream sources drift; CI is the single place
that proves reviewed support still builds and tests.

CI also validates the trusted runtime registry against the compatibility
manifest. A hash entry for a runtime executable is only valid when its
`name`/`version` matches a reviewed runtime release in the manifest. New runtime
releases may be detected automatically, but new trusted hashes must still land
through a reviewed change.

Linux entries represent Ubuntu `glibc` `x86_64` smoke coverage plus tracked
review work for `aarch64`, `musl`, and kernel series, not full Linux runtime
enforcement or production install support. Linux ELF exec-target scanning is
compiled as an explicit unsupported fail-closed boundary until ELF
classification is implemented. Privileged system mutation stays in the existing
CI/E2E path where it is explicit.

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
