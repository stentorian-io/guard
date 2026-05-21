# Existing alternatives

Sentinel applies default-deny outbound network enforcement to any command you
run in your terminal — not just package installs. Supply-chain attacks during
`npm install` are the motivating example, but the same protection covers build
scripts, dev servers, test suites, and anything else you wrap with `sentinel
wrap`. It's designed to work on your laptop today (macOS), on Linux tomorrow, and
in CI pipelines, giving you a single default-deny layer everywhere. It's not a
replacement for any of the tools below; it's the layer they're missing.

## EDR (CrowdStrike, SentinelOne, etc.)

Enterprise EDRs are designed for fleet-wide threat detection across an
organisation. They're excellent at what they do, but they're a poor fit for
this problem:

- **Cost and access.** EDR licenses are per-seat enterprise contracts. Most
  open-source developers, freelancers, and small teams don't have one.
- **Policy granularity.** EDRs operate at the endpoint level, not the process
  tree level. They can't distinguish "this `connect()` came from a postinstall
  script" from normal application traffic. Sentinel's policy is scoped to the
  exact command you wrap — and only that process tree.
- **Developer experience.** EDRs are managed by security teams, not individual
  developers. You can't tune policy per-project or add allow rules for a new
  registry without filing a ticket.
- **CI and cross-platform.** EDRs protect managed endpoints — they don't run in
  your CI pipeline or on a fresh Linux build box. Sentinel is designed to run
  anywhere you run commands: developer laptops, CI runners, and production
  build systems, across macOS and (soon) Linux.

If your organisation already runs an EDR, Sentinel complements it — the EDR
covers the broad endpoint, Sentinel gives you per-command default-deny
enforcement.

## LuLu

[LuLu](https://objective-see.org/products/lulu.html) is a great open-source
macOS firewall from Objective-See. It works at a different level:

- **Per-application, not per-process-tree.** LuLu prompts once for `node` and
  remembers the decision. But `node` is both your registry client and the
  runtime for malicious postinstall scripts — you can't allow one and deny the
  other. Sentinel's policy is per-destination and per-run, so registry traffic
  is allowed while unknown destinations are blocked.
- **Interactive prompts for everything.** LuLu prompts on first connection per
  binary. During a large `npm install`, you'd be buried in prompts for every
  transitive dependency's lifecycle script. Sentinel ships curated allowlists
  for major registries and CDNs so the common case is silent.
- **No threat intelligence.** LuLu doesn't know which destinations are
  associated with known-malicious packages. Sentinel bakes in IOCs from the
  OSV.dev malicious-packages dataset and updates them nightly.

LuLu and Sentinel can coexist — LuLu handles application-level firewall rules,
Sentinel handles per-command enforcement. LuLu is also macOS-only with no CI
story; Sentinel is designed for cross-platform use and headless CI environments.

## npm audit / cargo audit / pip-audit

Audit tools check for *known vulnerabilities in published packages*. That's
valuable, but it's a different problem:

- **Timing.** `npm audit` runs *after* install. Malicious postinstall scripts
  have already executed and exfiltrated by the time you see the advisory.
  Sentinel blocks exfiltration *as it happens*, during any command you wrap.
- **Coverage gaps.** Audit databases track CVEs in legitimate packages. A
  malicious package published under a typosquatted name with no CVE won't
  appear in any audit database — but its C2 traffic will hit Sentinel's
  default-deny policy.
- **Different threat model.** Audits catch "this package has a known bug."
  Sentinel catches "this package is trying to phone home." Both matter; they're
  not interchangeable.

Run audits *and* Sentinel — they cover orthogonal risks.

## Socket / Snyk / Dependabot

SCA (Software Composition Analysis) tools scan your dependency graph for known
vulnerabilities and sometimes flag suspicious package behaviour. They're useful
but operate at a fundamentally different point:

- **Pre-install analysis vs. runtime enforcement.** SCA tools analyse package
  metadata and source code *before* or *after* install. They can warn you
  about a suspicious `postinstall` script, but they can't stop it from running.
  Sentinel intercepts the actual network calls at runtime.
- **Heuristic vs. deterministic.** SCA tools use heuristics to flag "this
  package looks suspicious." Sentinel doesn't guess — if a process tries to
  connect to a destination that isn't on the allowlist, the connection is
  denied. No ML model, no risk score, no false-negative window.
- **Zero-day supply-chain attacks.** A brand-new malicious package that no
  scanner has seen yet will sail through SCA tools. Sentinel's default-deny
  policy blocks it on the first connection attempt to an unknown host.

SCA tools are your early warning system. Sentinel is your last line of defence —
and unlike most SCA integrations, it runs the same way on your laptop, in CI,
and on a build server.

## Lockfiles

Lockfiles pin exact versions so you don't accidentally pull a compromised
update. That's good practice, but it doesn't solve the problem:

- **First install.** The lockfile doesn't exist yet the first time you clone a
  project and run `npm install`. You're trusting every transitive dependency
  at whatever version the registry resolves.
- **Lockfile updates.** Every time you run `npm update`, `cargo update`, or
  equivalent, the lockfile changes. The new versions haven't been reviewed.
- **Compromised pinned versions.** If the exact version you pinned was already
  compromised (e.g. `ua-parser-js@0.7.29`), the lockfile faithfully reproduces
  the attack on every install.
- **No network enforcement.** A lockfile controls *which code* runs, not *what
  that code does*. A pinned package with a malicious postinstall script will
  still exfiltrate on every install. And lockfiles say nothing about what
  happens when you *run* the code, not just install it.

Use lockfiles. Also use Sentinel.
