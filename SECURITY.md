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
- Snapshot integrity bypass (HMAC forgery, tampering)
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
