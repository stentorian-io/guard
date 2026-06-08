# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No |

Only the most recent release receives security patches.
Once v1.0 ships, this table will be updated with a formal support window.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please use [GitHub's private vulnerability reporting](https://github.com/stentorian-io/guard/security/advisories/new)
to submit a report. This keeps the details confidential until a fix is available.

Alternatively, email **<security@stentorian.io>** with:

- A description of the vulnerability
- Steps to reproduce (minimal PoC preferred)
- Impact assessment (what an attacker can achieve)

## What to Expect

| Step | Timeline |
|------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 7 days |
| Patch or mitigation | Within 30 days (target) |

We will coordinate disclosure timing with you. Credit is given to reporters
by default unless you prefer to remain anonymous.

## Scope

The following are **in scope** as security issues:

- Bypasses that allow a non-hardened, DYLD-injectable process to exfiltrate
  data despite an active Stentorian Guard deny policy
- IPC protocol vulnerabilities (spoofing, replay, privilege escalation)
- Snapshot signature or trusted-signer bypass
- Daemon vulnerabilities (unauthorized rule injection, SQLite injection)
- Information disclosure through logs, snapshots, or IPC

The following are **known limitations**, not vulnerabilities:

- Hardened-runtime binaries (`/bin/bash`, `/usr/bin/python3`, etc.) rejecting
  DYLD injection — Stentorian Guard treats missing dylib coverage as a fail-closed
  coverage gap, but the platform restriction itself is not a bug
- Direct libc `syscall(SYS_CONNECT, ...)` calls bypassing libc symbol
  interposition — libc `syscall()` interposition is deferred; unknown native
  binaries containing raw syscall instruction bytes are classified T3 and fail
  closed before child creation
- Processes launched outside a `stt-guard wrap` subtree — Stentorian Guard is
  process-tree-scoped in v1, not system-wide

If you are unsure whether something is in scope, report it anyway.
We would rather triage a known limitation than miss a real vulnerability.

## Deployment Model

The repo-hosted installer deploys root-owned binaries, enrolls the invoking
user's device-local macOS Keychain rule-signing key,
registers that public signer with daemon state, and runs the daemon as a dedicated
`_stt_guard` service user (no login shell, no home directory — the same
convention as macOS's `_postgres` and `_mysql`). This is the only deployment
mode and prevents a compromised process from tampering with the guard itself.
Linux production install support is being designed around the same root-owned
and service-owned split with systemd, but it is not enabled until OS-backed
Linux signer enrollment and install-health validation are complete.

| Component | Path | Owner |
|---|---|---|
| Binaries | `/usr/local/libexec/stt-guard/` | `root:wheel` (755) |
| Trusted signer manifest | `/usr/local/libexec/stt-guard/trusted-rule-signers.tsv` | `root:wheel` (644) |
| Runtime state (DB, snapshots, public signing cache) | `/Library/Application Support/Stentorian Guard/` | `_stt_guard:_stt_guard` (700) |
| Logs | `/var/log/stt-guard/` | `_stt_guard:_stt_guard` (700) |
| LaunchDaemon | `io.stentorian.guard.daemon` | Root-managed |

**Attack surface with and without the installation:**

| Attack | Without installation | With installation |
|---|---|---|
| Replace binaries on disk | Code signing raises the bar | Root-owned — user can't write |
| Tamper with rule database | User-owned, writable | `_stt_guard`-owned, user can't write |
| Modify snapshot contents | Snapshot signature validates authenticity | `_stt_guard`-owned, written by daemon only |
| Delete denial logs | User-owned, deletable | `_stt_guard`-owned |
| Kill daemon and replace with rogue | Codesign peer auth detects | Can't kill a different UID without root; LaunchDaemon auto-restarts |
| Forge trusted policy artifacts | Daemon-writable state can be modified | Baseline/snapshot authenticity signing must use OS- or hardware-mediated private keys that the daemon cannot export or forge with |
| `sudo` inside monitored tree | Blocked (setuid check) | Blocked with explicit `PrivilegeEscalation` reason |

The IPC socket is world-writable — any process can connect — but the daemon
authenticates every connection via macOS audit tokens and codesign identity
verification (shipped in v0.7). The socket is the door; codesign is the lock.
Tagged IPC frames are plain CBOR frames over the authenticated Unix socket.
IPC authorization lives in peer authentication and daemon-side message policy;
policy artifact authenticity lives in OS- or hardware-mediated signatures.

Baseline/snapshot authenticity signing has a stricter key-storage requirement
than file ownership integrity: private signing keys must be OS- or
hardware-mediated (macOS Keychain, security key, TPM-backed key, or an equivalent
platform facility). On macOS, the installer creates or locates a device-local
macOS Keychain P-256 key in the invoking user's keychain before privilege
escalation, records the signer in a root-owned manifest under
`/usr/local/libexec/stt-guard/`, and mirrors only public signing metadata into
daemon state for operational lookups. Software-only private keys are not
acceptable because the daemon must be able to verify signatures without being
able to forge new trusted baselines if the daemon or its writable state is
compromised.

**Performance and UX impact:** the deployment has zero runtime overhead. The
protection is purely ownership and permissions on disk — the daemon, hook, and
policy engine execute the same code paths regardless. The user-visible
difference is the one-time privileged step performed by the installer during
setup.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits via private advisory or email
2. We confirm, assess severity, and develop a fix
3. We release the patch and publish a security advisory
4. Reporter is credited (unless they opt out)

We will not pursue legal action against researchers acting in good faith.

## License

This security policy applies to the Stentorian Guard project, licensed under
[MIT OR Apache-2.0](README.md#license).
