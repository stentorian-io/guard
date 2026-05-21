<p align="center">
  <!-- TODO: Replace with actual logo image -->
  <h1 align="center">Stentorian Guard</h1>
  <p align="center">
    <strong>Installing dependencies shouldn't feel like Russian Roulette</strong>
  </p>
  <p align="center">
    <a href="https://github.com/stentorian-io/guard/actions/workflows/validation.yml"><img src="https://github.com/stentorian-io/guard/actions/workflows/validation.yml/badge.svg?branch=main" alt="CI"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  </p>
</p>

---

<!-- TODO: Replace with animated terminal GIF showing Stentorian Guard in action -->
<!-- <p align="center"><img src="docs/assets/demo.gif" alt="Stentorian Guard demo" width="720"></p> -->

## Table of contents

- [Why Stentorian Guard?](#why-stentorian-guard)
  - [How exfiltration usually happens](#how-exfiltration-usually-happens)
  - [How Stentorian Guard prevents it](#how-stentorian-guard-prevents-it)
  - [Existing alternatives](#existing-alternatives)
- [Usage](#usage)
  - [Installation](#installation)
  - [Manual](#manual)
  - [Aliased](#aliased)
  - [Shell (recommended)](#shell-recommended)
  - [Reviewing activity](#reviewing-activity)
  - [Environment](#environment)
  - [Manuals](#manuals)
- [Coverage](#coverage)
  - [Platform support](#platform-support)
  - [Hardened deployment](#hardened-deployment)
  - [Threat intelligence](#threat-intelligence)
  - [Security expectations](#security-expectations)
- [Found Stentorian Guard useful?](#found-stentorian-guard-useful)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Why Stentorian Guard?

Compromised dependencies are silently stealing developer credentials at an unprecedented scale — and every project is a target. Stentorian Guard is a free, community-driven solution that cuts off exfiltration to C2 servers.

### How exfiltration usually happens

Every process you run in your terminal can make outbound network connections
without asking. Package installs execute code from hundreds of strangers.
Developer tools phone home with telemetry. Build scripts reach out to analytics
endpoints. Most of the time you have no visibility into what's leaving your
machine.

Consider a real-world scenario: a compromised npm package like `ua-parser-js`
(October 2021). An attacker publishes a hijacked version containing a
postinstall script. Here's what happens when you install it:

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant PM as npm install
    participant Reg as registry.npmjs.org
    participant Pkg as ua-parser-js (compromised)
    participant C2 as attacker server

    Dev->>PM: npm install
    PM->>Reg: Fetch package
    Reg-->>PM: ua-parser-js@0.7.29

    PM->>Pkg: Run postinstall
    Pkg->>C2: POST /exfil {hostname, user, keys}
    C2-->>Pkg: 200 OK
    Note over Dev,C2: The developer sees a normal install. The malicious payload runs silently, exfiltrates credentials, and the attacker has everything they need.
```

These attacks are accelerating. AI-driven development means more dependencies
pulled in faster, with less review — and a single compromised package propagates
like a worm through thousands of downstream projects. What happened to
[event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident),
[ua-parser-js](https://github.com/nicedreams/ua-parser-js-hijack-incident),
and [colors/faker](https://www.theverge.com/2022/1/9/22874949/developer-corrupts-open-source-libraries-colors-faker-protest)
is now happening across every ecosystem.

### How Stentorian Guard prevents it

Same scenario, but the developer runs `stt-guard wrap npm install`. Stentorian Guard
injects a hook library into the process tree that intercepts every outbound
connection before it leaves the machine:

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant SW as stt-guard wrap
    participant PM as npm install
    participant Hook as stt-guard-hook.dylib
    participant Reg as registry.npmjs.org
    participant Pkg as ua-parser-js (compromised)
    participant C2 as attacker server

    Dev->>SW: stt-guard wrap npm install
    SW->>PM: Spawn with DYLD_INSERT_LIBRARIES

    PM->>Hook: connect() → registry.npmjs.org
    Hook->>Hook: Policy check (curated allow ✓)
    Hook-->>Reg: Connection allowed
    Reg-->>PM: ua-parser-js@0.7.29

    PM->>Pkg: Run postinstall
    Pkg->>Hook: connect() → attacker server
    Hook->>Hook: Policy check (curated deny ✗)
    Note over Dev,C2: Attacker server is never reached — credentials stay on your machine.
```

Policy is evaluated in tier order:

1. **Curated Allow** — registries, CDNs
2. **Confirmed Deny** — threat-intel IOCs (confirmed malicious)
3. **User Deny** — your deny rules
4. **User Allow** — your allow rules
5. **Suspect Deny** — suspected IOCs (prompts if TTY)
6. **Default Deny**

Cache hits resolve in under 100 microseconds with no IPC.

- No kernel extensions or system extensions
- One-time `sudo stt-guard init` — hardened by default
- Works with any command or binary run from the terminal, not just package managers
- Root-owned binaries + `_stt_guard` service user — tamper-resistant

### Existing alternatives

Stentorian Guard applies default-deny outbound network enforcement to any command you
run in your terminal — not just package installs. Supply-chain attacks during
`npm install` are the motivating example, but the same protection covers build
scripts, dev servers, test suites, and anything else you wrap with `stt-guard
wrap`. It's designed to work on your laptop today (macOS), on Linux tomorrow,
and in CI pipelines, giving you a single default-deny layer everywhere. It's not a
replacement for EDRs, application firewalls, audit tools, SCA scanners, or
lockfiles; it's the layer they're missing.

For a detailed comparison with specific tools (CrowdStrike, LuLu, npm audit,
Socket/Snyk, lockfiles, and more), see [docs/alternatives.md](docs/alternatives.md).

## Usage

### Installation

```sh
brew install stentorian-io/tap/stt-guard
sudo stt-guard init
```

The init step creates a `_stt_guard` service user, deploys root-owned
binaries to `/usr/local/libexec/stt-guard/`, and starts the daemon as a
LaunchDaemon. This is the only deployment mode — it prevents a compromised
process from tampering with the guard itself. See
[Hardened deployment](#hardened-deployment) for details.

All other commands (`wrap`, `status`) require initialisation to be complete
and will refuse to run otherwise.

Or build from source — see [CONTRIBUTING.md](CONTRIBUTING.md#build) for
prerequisites and detailed instructions.

### Manual

> For trying out and setting baselines only. Use
> [shell](#shell-recommended) for day-to-day work.

Wrap individual commands on a case-by-case basis:

```sh
stt-guard wrap npm install
stt-guard wrap pip install -r requirements.txt
stt-guard wrap cargo build
stt-guard wrap ./some-script.sh
```

Build a baseline of expected network destinations for a known-clean project
with learn mode:

```sh
stt-guard wrap --learn npm install
```

This auto-allows all destinations encountered during the run and records them
as user rules. Only use this on a project you trust. Requires a TTY.

### Aliased

Alias specific toolchain commands so they always go through Stentorian Guard:

```sh
# In ~/.zshrc or ~/.bashrc
alias npm="stt-guard wrap npm"
alias pip="stt-guard wrap pip"
alias cargo="stt-guard wrap cargo"
```

A reasonable middle ground — your package managers are always protected, but
anything you haven't aliased runs unmonitored and malicious code that clears the
shell environment can still reach the network. Run the unwrapped command directly
(e.g. `command npm install`) to bypass the alias for a specific invocation.

### Shell (recommended)

Wrap your entire shell session so every command is protected by default:

```sh
# In ~/.zshrc or ~/.bashrc — must be first
stt-guard wrap --shell
```

This must appear before other commands in your shell configuration — anything
that runs before this line (e.g. other plugin initialisation, `eval` calls)
bypasses enforcement. The most intrusive option but also the most secure:
nothing leaves your machine without going through Stentorian Guard's policy.

### Reviewing activity

Check daemon health and hook integrity:

```sh
stt-guard status
```

Review denied connections from a specific run (the run UUID is printed when
`stt-guard wrap` completes):

```sh
stt-guard status denials <run-id>
```

Interactively walk through recent denials and create allow/deny rules:

```sh
stt-guard status review              # review most recent run
stt-guard status review <run-id>     # review a specific run
```

List active policy rules:

```sh
stt-guard status rules                    # user rules only
stt-guard status rules --include-built-in # include registry allowlists
```

Disable a built-in allow rule (e.g. when a registry is compromised):

```sh
stt-guard status rules --disable registry.npmjs.org --reason "suspected compromise"
```

Re-enable a previously disabled built-in rule:

```sh
stt-guard status rules --enable registry.npmjs.org
```

View persistence-write events (files written during a wrapped run):

```sh
stt-guard status persistence              # all events
stt-guard status persistence <run-id>
```

Look up threat-intel advisory details:

```sh
stt-guard status advisory <advisory-id>   # e.g. MAL-2025-3008
```

Stream the JSONL forensic log:

```sh
stt-guard status logs
```

### Environment

Stentorian Guard uses these environment variables for advanced configuration
and source-build workflows:

| Variable | Purpose |
| --- | --- |
| `STT_GUARD_STATE_DIR` | Override the state directory used by the CLI, daemon, and hook. Defaults to `~/Library/Application Support/Stentorian Guard`. |
| `STT_GUARD_HOOK_DYLIB` | Override the hook dylib path used by `stt-guard wrap`. Mostly useful for source builds and tests. |
| `RUST_LOG` | Control CLI and daemon logging verbosity. |

`STT_GUARD_SNAPSHOT_MANIFEST` is an internal per-run variable injected by
`stt-guard wrap` into wrapped processes. Development and test harness variables
use the `STT_GUARD_TEST_*` prefix, plus `STT_GUARD_E2E_NODE` for selecting a
Node.js binary in end-to-end tests; they are not part of the stable user
interface.

### Manuals

Running `stt-guard` with no arguments prints help with all available commands
and options:

```sh
stt-guard
```

```
Usage: stt-guard <COMMAND>

Commands:
  init    Initialise Stentorian Guard (hardened mode). Requires root
  wrap    Wrap a command under default-deny network enforcement
  status  Inspect daemon health, rules, denials
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Detailed documentation is also available via man pages:

```sh
man stt-guard    # CLI usage
man stt-guard-daemon   # daemon internals
```

## Coverage

### Platform support

| Platform | Version       | Status        | Mechanism                | Notes                                                                                                                                                                                                                                                     |
| -------- | ------------- | ------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS    | 13+ (Ventura) | **Supported** | DYLD injection           | Primary platform, tested in CI                                                                                                                                                                                                                            |
| macOS    | 12 (Monterey) | Best-effort   | DYLD injection           | Not tested in CI                                                                                                                                                                                                                                          |
| Linux    | —             | Planned (v2)  | LD_PRELOAD / seccomp-bpf | [Tracking issue](https://github.com/stentorian-io/guard/issues/2)                                                                                                                                                                                      |
| Windows  | —             | Not planned   | —                        | Windows restricts userspace library injection behind kernel-mode driver signing and security features that require paid enterprise certificates. There is no equivalent to DYLD or LD_PRELOAD available to open-source tools without elevated privileges. |

### Hardened deployment

`stt-guard init` deploys in hardened mode: binaries are root-owned and
the daemon runs as a dedicated `_stt_guard` service user (no login shell,
no home directory — same convention as macOS's `_postgres` and `_mysql`).
This prevents a compromised process from tampering with the guard itself.

| Component | Path | Owner |
|---|---|---|
| Binaries | `/usr/local/libexec/stt-guard/` | `root:wheel` (755) |
| Runtime state (DB, snapshots, HMAC keys) | `/Library/Application Support/Stentorian Guard/` | `_stt_guard:_stt_guard` (700) |
| Logs | `/var/log/stt-guard/` | `_stt_guard:_stt_guard` (700) |
| LaunchDaemon | `io.stentorian.guard.daemon` | Root-managed |

**What hardened mode protects against:**

| Attack | Without hardened mode | With hardened mode |
|---|---|---|
| Replace binaries on disk | Code signing raises the bar | Root-owned — user can't write |
| Tamper with rule database | User-owned, writable | `_stt_guard`-owned, user can't write |
| Modify snapshot contents | HMAC validates integrity | `_stt_guard`-owned, written by daemon only |
| Delete denial logs | User-owned, deletable | `_stt_guard`-owned |
| Kill daemon and replace with rogue | Codesign peer auth detects | Can't kill a different UID without root; LaunchDaemon auto-restarts |
| Steal HMAC key material | User-readable | `_stt_guard`-readable only (700) |
| `sudo` inside monitored tree | Blocked (setuid check) | Blocked with explicit `PrivilegeEscalation` reason |

The IPC socket is world-writable — any process can connect — but the daemon
authenticates every connection via macOS audit tokens and codesign identity
verification (shipped in v0.7). The socket is the door; codesign is the lock.

**Performance and UX impact:** hardened mode has zero runtime overhead. The
protection is purely ownership and permissions on disk — the daemon, hook, and
policy engine execute the same code paths regardless. The only user-visible
difference is the one-time `sudo stt-guard init` during setup.

### Threat intelligence

Stentorian Guard ships with threat intelligence sourced from
[OSV.dev malicious-package advisories](https://osv.dev) (the OSSF Malicious
Packages dataset). A nightly CI job pulls new advisories, commits them to the
repository, and the data is baked into the binary at compile time — no runtime
network fetches, no phone-home. Hand-curated abuse-pattern rules (e.g. shared
hosting domains commonly used for exfiltration) supplement the automated feed.

| Signal                      | Action                                       | Source                           |
| --------------------------- | -------------------------------------------- | -------------------------------- |
| Confirmed malicious package | **Default deny**                             | OSV.dev advisories               |
| Suspected malicious host    | **Flagged** — surfaces an interactive prompt | Hand-curated abuse patterns      |
| Known-good registry/CDN     | **Allow**                                    | Curated allowlists per ecosystem |

### Security expectations

Stentorian Guard is defense-in-depth, not a sandbox. It stops the realistic,
high-volume attack — supply-chain packages that phone home through standard
networking calls — which is how the overwhelming majority of these compromises
work. The goal is to make that attack class fail by default.

In [hardened mode](#hardened-deployment) (the default), a local attacker needs
root to tamper with the guard's binaries, database, or logs. Without root, the
remaining attack surface is DYLD stripping (a parent process removing the
injection variable before spawning children) and runtime memory patching of the
in-process hook — both require deliberate, targeted effort beyond what
supply-chain malware attempts.

It is not designed to stop a sufficiently determined attacker who can exploit
the kernel or target infrastructure outside the process tree. On macOS,
unknown native binaries that contain raw syscall instruction bytes fail closed
at exec time; a future design will investigate non-fail-closed alternatives for
that T3 class. The [security policy](SECURITY.md) documents the full threat
model, known platform constraints, and what is (and isn't) considered a
vulnerability. Read it before assuming Stentorian Guard is a sandbox — it isn't one,
and we are upfront about where the boundaries are.

## Found Stentorian Guard useful?

Stentorian Guard is free and always will be — it's a community-driven effort to protect
developers from supply-chain attacks. If it's saved you from a sketchy package
or just gives you peace of mind, consider
[sponsoring the project](https://github.com/sponsors/stentorian-io).

<!-- TODO: Add sponsorship badge when set up -->

## Changelog

See [GitHub Releases](https://github.com/stentorian-io/guard/releases) for
release history.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture details, crate map, IPC
protocol documentation, and build instructions.

## Licensing

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

---

<p align="center">
  Built by <a href="https://stentorian.io">Stentorian</a> — because developers deserve nice things.
</p>
