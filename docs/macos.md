# macOS Support

macOS is the primary supported platform for Stentorian Guard.

## Status

| macOS version | Status |
| --- | --- |
| macOS 13 Ventura and newer | Supported |
| macOS 12 Monterey | Best-effort |
| macOS 11 Big Sur and older | Historical tracking only |

Supported CPU architectures are `arm64`/`aarch64` and `x86_64`.

The supported Rust targets are `aarch64-apple-darwin` and
`x86_64-apple-darwin`. Other Apple target names may be tracked for review, but
tracking does not mean runtime support.

## Enforcement Model

macOS enforcement uses `DYLD_INSERT_LIBRARIES` to load the guard hook into
wrapped processes. The hook interposes networking, process, and persistence
entry points and asks the daemon for policy decisions when needed.

The daemon uses macOS-native peer identity signals, including audit tokens and
code-signing information, so enforcement decisions are based on kernel-sourced
process identity rather than caller-provided claims.

Hardware-backed signing is required for baseline and snapshot signing. On macOS,
the production path is Secure Enclave or a compatible security key.

## Compatibility Assumptions

macOS compatibility is not treated as a permanent kernel ABI promise. The parts
Stentorian Guard depends on can drift between releases:

- `dyld` behavior and `DYLD_*` environment handling
- hardened runtime and library validation behavior
- System Integrity Protection restrictions
- audit-token and peer-authentication behavior
- Mach-O CPU subtype names and loader behavior
- Xcode SDK and Rust target support

For that reason, the compatibility tracker reviews new macOS, CPU architecture,
Xcode, Rust, and LLVM entries before the project treats them as covered.

## Support Decisions

Stentorian Guard avoids kernel extensions and system extensions on macOS. The
project is designed to run from user space and fail closed when injection or
identity checks cannot provide the guarantees enforcement needs.

Exec-time classification blocks unsupported Mach-O shapes, unknown native CPU
subtypes, unknown non-Mach-O formats, unreadable paths, malformed scanner
inputs, and native binaries with known raw syscall instruction bytes. Clean
native Mach-O files are classified separately from shebang scripts. Mach-O
scanning is compiled only for macOS, and raw syscall instruction matching uses
the native Rust target architecture's pattern table.

Shebang scripts are the reviewed exception: they remain allowed because the
interpreter is the runtime that receives the hook and is classified at exec
time.

Hardened-runtime children that strip `DYLD_*` injection are treated as coverage
gaps. The intended behavior is to detect that gap before relying on a missing
hook and block or report it rather than silently allowing network access.

`arm64e` is tracked because it can appear in Apple tooling and Mach-O metadata,
but it is not a separate supported runtime target today.

## What Would Change Support

Support should be revisited when Apple changes `dyld`, hardened runtime,
library validation, peer identity, or supported CPU architecture behavior in a
way that affects hook loading or fail-closed enforcement.

The checked-in compatibility manifest records reviewed OS and architecture
entries. It is a review ledger, not a grant of support by itself.
