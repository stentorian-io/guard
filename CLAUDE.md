<!-- GSD:project-start source:PROJECT.md -->
## Project

**Sentinel**

Sentinel is a free, open-source macOS supply-chain firewall that enforces default-deny on outbound network connections from package-install subtrees. The user runs `sentinel run npm install …` (or `pip`, `cargo`, etc.) and Sentinel sandboxes that subtree's network egress — registries are allowed, anything else is denied or surfaces an interactive prompt. v1 is process-tree-only and uses DYLD library injection (no system extension, no kernel components). Whole-machine mode is deferred to v2.

**Core Value:** **When a compromised package tries to phone home during install, Sentinel blocks it cold and tells the user what happened.** That's the one thing that must work. Every other feature serves this.

### Constraints

- **Platform**: macOS only in v1
- **Tech stack**: Rust everywhere — CLI, daemon (`sentineld`, user-level LaunchAgent), and the `libsentinel_hook.dylib` injected into wrapped processes
- **Enforcement mechanism**: DYLD library injection via `DYLD_INSERT_LIBRARIES` — covers the libc-using libc real-world supply-chain attack class but not hardened-runtime children or raw-syscall malware
- **Privilege**: no root/admin required for enforcement; daemon runs as the user
- **Privacy**: Sentinel is an anti-exfiltration tool — it cannot itself become a telemetry pipe. Threat-intel feed pulls only; no upstream submissions in v1; no analytics in the daemon
- **UX**: terminal-only — no GUI, no menu bar, no web dashboard in v1
- **Performance**: hook overhead must be negligible — under 100µs per intercepted call (in-process lookup against an mmap'd snapshot, no IPC on the hot path)
- **Bypass acknowledgement**: this is a defense-in-depth layer, not a sandbox — sufficiently advanced malware can use raw syscalls or exec into hardened binaries to escape. Sentinel must catch the realistic supply-chain attack class, not the theoretical 100%
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Executive Recommendation (one-line per layer)
| Layer | Pick | Confidence |
|---|---|---|
| Languages | **Swift 6.x throughout** (CLI, daemon, system extension) | HIGH |
| Network enforcement | **NetworkExtension content filter** — `NEFilterDataProvider` + `NEFilterControlProvider` packaged as a System Extension | HIGH (Apple-mandated) |
| Process supervisor | **Endpoint Security framework** (paired with NE for process-tree tracking) | MEDIUM-HIGH |
| Lifecycle | **`OSSystemExtensionRequest`** for the NE bundle, **`SMAppService`** for the helper daemon | HIGH |
| CLI ↔ daemon IPC | **`NSXPCConnection`** with **SwiftyXPC** wrapper (Codable + async/await) | MEDIUM-HIGH |
| Argument parsing | **`apple/swift-argument-parser` 1.7.x** | HIGH |
| Logging | **OSLog `Logger`** (unified logging) inside daemon/extension; mirrored via `swift-log` `LogHandler` for tests | HIGH |
| Build | **Swift Package Manager + Tuist 4.x** (use Tuist where SwiftPM cannot — system extension app target) | MEDIUM |
| Testing | **Swift Testing** for new tests, **XCTest** for any UI/perf | HIGH |
| Distribution | **Developer ID Application cert + notarytool + Homebrew Cask** (private tap initially) | HIGH |
| Threat-intel clients | **Native URLSession clients** for OSV.dev, URLhaus, ThreatFox, GitHub GraphQL — Apache-2.0/CC0 sources | MEDIUM |
## Recommended Stack
### Core Technologies
| Technology | Version | Purpose | Why Recommended |
|---|---|---|---|
| **Swift** | 6.1+ (Xcode 16.3+) | All targets: CLI, daemon, NE system extension | Apple-mandated for Network Extension and System Extension SDKs. Swift 6 strict concurrency model is well-suited for filter providers (which are heavily callback-driven). Objective-C interop is fine but pure-Swift is now the community standard since Apple's own sample code (e.g. `SimpleFirewall`) is Swift-first. |
| **macOS deployment target** | 14.0 (Sonoma) minimum | Per PROJECT.md constraint | macOS 14 has stable System Extension framework, full NEFilterDataProvider API, mature `SMAppService`, and `sourceProcessAuditToken` on `NEFilterFlow`. macOS 15 (Sequoia) adds explicit prevention of user-disable for system extensions and improved filter stability — recommend 14.0 floor with 15.0+ feature flags. |
| **NetworkExtension framework** | macOS 14+ system framework | The actual content filter — sees every TCP/UDP flow, decides allow/deny | This is **the only Apple-supported way** to do system-wide socket-level egress filtering on modern macOS. Replaces deprecated PF rules and forbidden kernel extensions. Two providers: `NEFilterDataProvider` (sees flows, makes decisions, runs sandboxed) and `NEFilterControlProvider` (talks to user app, can update rules). Both must live in a System Extension bundle. **MUST-USE** — no alternative. |
| **SystemExtensions framework** | macOS 14+ system framework | Lifecycle: install/activate/uninstall the .systemextension bundle | `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:queue:)` + `OSSystemExtensionManager.shared.submitRequest(_:)`. Triggers the System Settings approval prompt (one-time UX cost, then invisible). Bundle lives at `Contents/Library/SystemExtensions/<bundleID>.systemextension` inside the host app. **MUST-USE**. |
| **Endpoint Security framework** | macOS 14+ system framework | Process-tree tracking: `ES_EVENT_TYPE_NOTIFY_FORK`, `NOTIFY_EXEC`, `NOTIFY_EXIT` | **Strongly recommended for Sentinel's process-tree mode.** NEFilterFlow gives you `sourceProcessAuditToken` (the immediate process), but reconstructing the parent chain reliably during `npm install` (where `npm` → `node` → `sh` → `curl` happens fast, with fork+exec races) is brittle without ES. ES gives you authoritative fork/exec events with `responsible_audit_token`, which is exactly the parent-attribution Sentinel needs. **Caveat:** requires `com.apple.developer.endpoint-security.client` entitlement, which **Apple manually approves per developer** — typically takes weeks-to-months and must be re-approved for Developer ID distribution. This is the single biggest schedule risk. |
| **ServiceManagement framework (`SMAppService`)** | macOS 13+ | Register the optional helper daemon (e.g. for threat-feed updater) | `SMJobBless` is **deprecated since macOS 13**. `SMAppService` is the modern replacement — daemon plist lives in `Contents/Library/LaunchDaemons/`, the executable lives in `Contents/MacOS/`, no system-directory copies, removed when app is removed. Required only if threat-feed updater runs as a separate root-privileged daemon; if the system extension itself fetches feeds (it has network), this can be skipped. |
### Supporting Libraries
| Library | Version | Purpose | When to Use |
|---|---|---|---|
| **apple/swift-argument-parser** | **1.7.1** (latest, July 2025) | CLI subcommand parsing for `sentinel run / status / logs / approve / npm install …` | Industry standard for Swift CLIs; Apple maintains it. Built-in completion-script generation (bash/zsh/fish), aliases, async support. Use everywhere. |
| **apple/swift-log** | 1.6.x | `Logger` API abstraction — lets tests inject a capturing handler, prod uses OSLog backend | Optional but recommended. Pair with `chrisaljoudi/swift-log-oslog` for the OSLog backend in production. Pure `os.Logger` (the OSLog `Logger` type) is also fine if you don't need backend swapping. |
| **CharlesJS/SwiftyXPC** | Latest | Type-safe XPC: Codable messages + Swift concurrency on top of NSXPCConnection | The raw `NSXPCConnection` API is `@objc` protocol-based and awkward from Swift. SwiftyXPC wraps it with Codable structs and `async throws` methods. **Use this** instead of writing `@objc` protocols by hand. (Alternative: `Alkenso/sXPC` — similar idea, less active.) |
| **apple/swift-async-algorithms** | 1.0+ | Stream-processing for ES events and NE flows; debouncing, merging | Useful for combining ES fork/exec event streams with NE flow streams. Optional but materially simplifies the supervisor. |
| **apple/swift-collections** | 1.1+ | `OrderedDictionary`, `Deque` for in-memory rule cache and process-tree map | Standard Swift collection extensions. Low-cost dependency. |
| **apple/swift-crypto** | 3.x | Hashing for binary identity (CDHash extraction supplements Apple-provided code-signing checks) | If Sentinel pins rules to "the `npm` binary with this CDHash," you'll want SHA-256 over Mach-O segments. macOS provides `SecCodeCopySigningInformation` natively too. |
### Threat-Intel Feed Clients
| Feed | Format | Approach |
|---|---|---|
| **OpenSSF Malicious Packages** | OSV format (JSON), accessible via osv.dev or directly via the `ossf/malicious-packages` GitHub repo | Two paths: (1) **Pull the repo** (`git clone --depth=1`) and parse OSV JSON files directly — most resilient to API changes, license is Apache-2.0. (2) **osv.dev REST API** at `https://api.osv.dev/v1/query` — easier but rate-limited. Recommend (1) for a daily background sync, (2) only for ad-hoc lookups. |
| **abuse.ch URLhaus** | CSV / JSON download, public API | Public download endpoints documented at urlhaus.abuse.ch/api. **Note the May 2024 change:** abuse.ch feeds now require a free Auth-Key from Spamhaus. URLhaus also publishes a downloadable hostfile and CSV — pull these on a 5-minute cron. |
| **abuse.ch ThreatFox** | JSON POST API | Same Auth-Key requirement. Existing third-party Go client `github.com/rollwagen/abusech/threatfox` exists as a reference; Swift port is trivial — POST JSON to `threatfox-api.abuse.ch/api/v1/`, decode IOC arrays. |
| **GitHub Advisory Database** | GraphQL API (or download `github/advisory-database` repo) | GitHub PAT required (no scopes). For Sentinel's use (lookup-by-ecosystem+package-name), the **repo-clone approach** is again better than GraphQL — the repo is well-organized, tractable in size, and updates daily. Use GraphQL only if you need real-time freshness. |
### Persistence
| Library | Version | Purpose | Notes |
|---|---|---|---|
| **GRDB.swift** | 7.x | SQLite for: rule store, IOC cache, learn-mode baseline, audit log | Most ergonomic Swift SQLite library — Codable rows, migrations, observation. Alternative: SQLite.swift (also fine, less active). Avoid Core Data — the system extension runs sandboxed and Core Data gets fussy in extensions. |
### Development Tools
| Tool | Purpose | Notes |
|---|---|---|
| **Xcode 16.3+** | IDE, code signing, system-extension scheme | Required — system extensions cannot be built via SwiftPM alone. The host-app target must be an Xcode project. |
| **Tuist 4.x** | Generate the Xcode project from Swift `Project.swift` files | **Recommended** because the project has 3+ targets (CLI, daemon if separated, system extension, host wrapper app for sysext install) plus shared modules. Tuist makes this declarative, diff-friendly, and avoids `.xcodeproj` merge pain. Alternative: hand-maintain `.xcodeproj` if team prefers (smaller footprint, more friction). |
| **Swift Package Manager** | Package internal modules (`SentinelCore`, `SentinelRules`, `SentinelFeeds`) | SPM cannot build the .systemextension bundle, but it's fine for shared library targets that the Xcode targets depend on. Tuist supports SPM dependencies natively. |
| **swift-format** | Code formatting | Apple's official formatter, integrates with SwiftPM. |
| **SwiftLint** | Style enforcement | Optional. Use Apple's style guide; SwiftLint adds opinionated rules. |
| **`xcrun notarytool`** | Submit to Apple notary service (replaces deprecated `altool`) | Required. CI script: build → codesign deep → ditto-zip → `notarytool submit --wait` → `stapler staple`. |
| **`systemextensionsctl`** | List/uninstall installed system extensions during development | `sudo systemextensionsctl developer on` is required to load unsigned extensions during local dev (must disable SIP). For CI/Release: signed-and-notarized only. |
| **GitHub Actions, macOS-14 runner** | CI signing + notarization | Apple Developer cert imported via `apple-actions/import-codesign-certs`. The notarization step requires `APP_STORE_CONNECT_API_KEY` secret. |
| **Homebrew Cask** | Distribution | Cask is correct for an app + system extension bundle. Note: as of Homebrew 5.0 (2025), all casks must be signed-and-notarized — already a requirement for system extensions, so no extra work. Start with a private tap (`brew tap sentinel-app/sentinel`), graduate to homebrew/cask when stable. |
## Installation
# Project bootstrap (Tuist)
# CLI dev loop (no system extension yet)
# Full app + system extension build
# Notarize
# Local dev: enable unsigned system extension loading (one time, requires SIP off)
### SwiftPM dependencies (`Package.swift` for shared modules)
## Alternatives Considered
| Recommended | Alternative | When the Alternative Is Better |
|---|---|---|
| Swift everywhere | **Go or Rust CLI talking to Swift daemon over Unix socket** | Only if the team has zero Swift experience and *very* deep Go/Rust experience. Cost: +1 language toolchain in CI, +1 IPC schema definition, harder to debug across the boundary. The system extension MUST be Swift/ObjC, so you're already paying for Swift. **Recommendation: don't split unless necessary.** |
| `NSXPCConnection` (via SwiftyXPC) | **Unix domain socket + length-prefixed JSON / gRPC-Swift** | If you want an IPC channel that works identically on Linux for a future port. Cost: re-implement auth (XPC gives you peer audit-token for free), re-implement type safety, re-implement reconnection. **XPC is the right macOS-native choice.** |
| Endpoint Security for process attribution | **Walk parent chain via `proc_pidinfo` and `audit_token_to_pid`** in the NE provider only | If the ES entitlement approval is denied or schedule-blocking. Cost: PID-reuse races, missing the fork between exec calls, brittle parent-chain reconstruction. Acceptable for v1 fallback if ES is blocked, but expect false positives/negatives. **ES is the correct architecture; have a fallback plan.** |
| `SMAppService` for daemon | **`SMJobBless`** | **Never.** Deprecated since macOS 13. New code must use `SMAppService`. |
| `OSSystemExtensionRequest` | **Kernel extension (kext)** | **Never.** Kexts are deprecated since macOS 10.15.4 and require user to boot with reduced security on Apple Silicon. Network kexts are flatly unsupported on modern macOS. |
| Tuist | **Plain `.xcodeproj`** hand-maintained | Smaller projects (single CLI), or teams allergic to extra tooling. For Sentinel's multi-target setup, Tuist pays for itself within a week. |
| Tuist | **XcodeGen** | XcodeGen uses YAML, Tuist uses Swift. Both work. Tuist has stronger SPM integration and better caching. Use XcodeGen if the team prefers YAML. |
| Swift Testing | **XCTest** | Use XCTest where you need: performance tests (`measure`), UI tests, or Objective-C interop. Swift Testing for everything else. |
| GRDB.swift | **SQLite.swift** / **raw `sqlite3` C API** | Both work. GRDB is more ergonomic and actively maintained. Avoid Core Data in the system extension (sandboxing + container issues). |
| URLSession + Codable for feeds | **STIX/TAXII client (e.g. libtaxii bindings)** | Only if the feed providers expose TAXII servers. **None of the four feeds in scope do** — they're plain JSON/CSV. Don't add STIX complexity for no value. |
| Direct repo-clone of OSV / GHAdvisory | **osv.dev API + GitHub GraphQL** | Use APIs only when you need realtime freshness. Repo-clone is more resilient to API changes, no rate limits, and lets us version-pin the threat data alongside the binary. |
## What NOT to Use
| Avoid | Why | Use Instead |
|---|---|---|
| **Kernel extensions (kexts)** | Deprecated since macOS 10.15.4. Network kexts (NKE) gone entirely on Apple Silicon. Cannot be notarized. | `NEFilterDataProvider` system extension. |
| **`pfctl` / `pf.conf` rules** | PF is still in macOS but unsupported as a third-party API. No process-identity awareness. Apple has signaled multiple times that PF is internal-use. | `NEFilterDataProvider`. |
| **`dyld` interpose / `DYLD_INSERT_LIBRARIES`** | Defeated by hardened runtime (which is required for notarization). Only works for non-hardened binaries — exactly the binaries you don't need to protect. | OS-level filter (NE). |
| **`SMJobBless`** | Deprecated since macOS 13. Helper installation API. | `SMAppService.daemon(plistName:).register()`. |
| **`SMLoginItemSetEnabled`** | Deprecated since macOS 13. | `SMAppService.loginItem(identifier:).register()` (if you ever add a login item). |
| **`NSLog` / `print` in extension** | Won't show in Console app reliably; no metadata; no privacy redaction. | `os.Logger(subsystem:category:)`. |
| **`altool`** for notarization | Deprecated November 2023. | `xcrun notarytool`. |
| **Core Data inside the system extension** | Sandboxing + container path issues; CD assumes it owns its store. | GRDB / SQLite.swift with an explicit App Group container. |
| **`content-filter-provider`** entitlement value | Wrong value for Developer-ID-distributed system extensions. | **`content-filter-provider-systemextension`** — the `-systemextension` suffix is required for independent (non-MAS) distribution. This is a common shipping-day pitfall. |
| **App Sandbox** for the host wrapper app | The wrapper app needs to install the system extension and talk XPC to it across processes. App Sandbox makes this strictly harder; gains nothing for a Developer-ID-distributed app. | Hardened runtime (required) without App Sandbox. |
| **Distribution via Mac App Store** | Endpoint Security entitlement is **explicitly not granted** for MAS apps. Network Extension content filters are restricted on MAS too. | Developer ID + notarytool + Homebrew Cask / direct DMG. |
| **`NEFilterPacketProvider`** for Sentinel's use case | Layer-2 packet provider. Sentinel works at the flow level (host/port), not packet level — packet-level forces TLS payload concerns Sentinel explicitly does NOT want. | `NEFilterDataProvider` (flow level). |
| **Protocol Buffers / gRPC for CLI ↔ daemon** | XPC already gives you audit-token-based auth, type safety via Codable, and reconnection. gRPC needs all of this rebuilt and is overkill for one host. | `NSXPCConnection` via SwiftyXPC. |
## Stack Patterns by Variant
- System extension contains both an NEFilterDataProvider and an ES client
- ES events feed a process-tree supervisor that maps `pid → ProcessIdentity{ binary, parent, root_invocation }`
- NE provider consults the supervisor on each new flow to determine the correct rule scope
- Process-tree mode (`sentinel npm install …`) is implemented by tagging `npm`'s pid as a "root invocation," ES fork/exec events propagate the tag to descendants
- Use only `NEFilterFlow.sourceProcessAuditToken` + `audit_token_to_pid()` + `proc_pidpath()` + `proc_pidinfo(PROC_PIDTBSDINFO)` (for ppid)
- Walk parent chain on demand at flow time
- Accept higher false-negative rate when fork→exec races outpace flow handling
- Document the limitation; pursue ES approval as a Phase 2 goal
- Process-tree mode still works but with reduced fidelity; whole-machine mode is unaffected
- CLI does NOT directly invoke a custom posix_spawn wrapper. Instead:
- **Why this beats `posix_spawnattr_*` tricks:** ES gives reliable parent-attribution even when the child re-execs into another binary; no env-var inheritance hack needed.
- Take advantage of the new `RestrictedSystemExtensions` MDM key shape (informs admins how to lock Sentinel on)
- Filter stability fixes mean fewer reconnect/replay edge cases — can simplify reconnect logic
- Document supported version explicitly: "Sentinel requires macOS 14.0; macOS 15.0+ recommended"
- Per WWDC25, ES alone can substitute for NE for some firewall use cases (objective-see's writeup demonstrates this on 26.4+). **Not recommended for v1** — undocumented, 15-second deadline, still requires ES entitlement. Mention as a future simplification path.
## Version Compatibility
| Package | Compatible With | Notes |
|---|---|---|
| Swift 6.1 | Xcode 16.3+, macOS 14+ deployment | Strict concurrency on by default; expect to annotate `@MainActor` and `Sendable` carefully in the system extension. |
| swift-argument-parser 1.7.x | Swift 5.9+, macOS 12+ | No issue with Swift 6 strict concurrency. |
| GRDB.swift 7.x | Swift 6, macOS 12+ | v7 is Swift 6 ready; v6 if stuck on Swift 5. |
| SwiftyXPC | Swift 5.9+, macOS 11+ | Active maintenance; check release notes for Swift 6 strict-concurrency status before upgrading. |
| Tuist 4.x | Xcode 16+, Swift 5.10+ | Tuist 4 dropped support for older Xcodes. |
| Endpoint Security entitlement | macOS 10.15.4+ for runtime, but distribution version must match approval | Re-apply when changing distribution channel (dev → Developer ID). |
| NetworkExtension content filter | macOS 10.15+ runtime | `sourceProcessAuditToken` available in modern SDKs; verify per-call availability in Xcode. |
## Sources
### Apple official (HIGH confidence)
- [Apple — `NEFilterDataProvider`](https://developer.apple.com/documentation/networkextension/nefilterdataprovider) — content filter data provider class
- [Apple — `NEFilterProvider`](https://developer.apple.com/documentation/networkextension/nefilterprovider) — base class hierarchy
- [Apple — Content filter providers](https://developer.apple.com/documentation/networkextension/content-filter-providers) — overview
- [Apple — `NEFilterFlow.sourceProcessAuditToken`](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceprocessaudittoken) — process audit token API
- [Apple — `OSSystemExtensionRequest`](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequest) — activation API
- [Apple — System Extensions](https://developer.apple.com/documentation/systemextensions) — framework overview
- [Apple — Installing System Extensions and Drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers/) — bundle structure
- [Apple — Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity) — ES API reference
- [Apple — `ES_EVENT_TYPE_NOTIFY_FORK`](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_fork)
- [Apple — `com.apple.developer.endpoint-security.client` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
- [Apple — Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Apple — Configuring network extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions) — Developer ID `-systemextension` suffix detail
- [Apple — Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple — Debugging and testing system extensions](https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions) — `systemextensionsctl developer on`
- [Apple — `systemextensionsctl(8)` man page](https://keith.github.io/xcode-man-pages/systemextensionsctl.8.html)
- [Apple — Build an Endpoint Security app (WWDC20)](https://developer.apple.com/videos/play/wwdc2020/10159/)
- [Apple — Network Extensions for the Modern Mac (WWDC19)](https://developer.apple.com/videos/play/wwdc2019/714/)
- [Apple — Filter and tunnel network traffic with NetworkExtension (WWDC25)](https://developer.apple.com/videos/play/wwdc2025/234/)
- [Apple — System Extensions and DriverKit (WWDC19)](https://developer.apple.com/videos/play/wwdc2019/702/)
### Apple-maintained tooling (HIGH confidence)
- [`apple/swift-argument-parser`](https://github.com/apple/swift-argument-parser) — latest 1.7.1 (verified via redirect)
- [`apple/swift-log`](https://github.com/apple/swift-log)
- [Swift.org — Build a CLI with SwiftPM](https://www.swift.org/getting-started/cli-swiftpm/)
### Independent technical writeups (MEDIUM confidence — verified against Apple docs)
- [SwiftLee — Network Extension Debugging on macOS](https://www.avanderlee.com/debugging/network-extension-debugging-macos/)
- [SwiftLee — OSLog and Unified logging](https://www.avanderlee.com/debugging/oslog-unified-logging/)
- [Gertrude — Get user id from `NEFilterFlow.sourceAppAuditToken`](https://gimrude.app/blog/macos-user-id-from-sourceappaudittoken) — `audit_token_to_*` patterns
- [theevilbit — `SMAppService` overview](https://theevilbit.github.io/posts/smappservice/) — confirms `SMJobBless` deprecation
- [Apriorit — System Extensions and DriverKit](https://www.apriorit.com/dev-blog/669-mac-system-extensions)
- [Scott Knight — System Extension internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [objc.io — XPC](https://www.objc.io/issues/14-mac/xpc/) — XPC patterns
- [objective-see — Writing a Process Monitor with ESF](https://objective-see.org/blog/blog_0x47.html)
- [objective-see — Building a Firewall via Endpoint Security](https://objective-see.org/blog/blog_0x86.html) — ES-as-firewall on macOS 26+
- [The Mitten Mac — Threat Hunting PIDs Within Apple's ES API](https://themittenmac.com/threat-hunting-pids-within-apples-es-api/) — `responsible_audit_token`
- [Tuist — Why generate Xcode projects in 2025](https://tuist.dev/blog/2025/02/25/project-generation)
- [Tuist — What Swift Build means for the ecosystem](https://tuist.dev/blog/2025/02/03/swift-build)
### Community libraries (MEDIUM confidence)
- [`CharlesJS/SwiftyXPC`](https://github.com/CharlesJS/SwiftyXPC) — Codable XPC wrapper
- [`Alkenso/sXPC`](https://github.com/Alkenso/sXPC) — alternative type-safe XPC
- [`chrisaljoudi/swift-log-oslog`](https://github.com/chrisaljoudi/swift-log-oslog) — swift-log → OSLog backend
- [LuLu (objective-see) — open-source firewall reference architecture](https://objective-see.org/products/lulu.html)
- [Brandon7CC/mac-monitor — open-source ES app reference](https://github.com/Brandon7CC/mac-monitor)
### Threat-feed sources (HIGH on protocol/format, LOW on Swift client availability)
- [OSV schema](https://ossf.github.io/osv-schema/)
- [osv.dev API](https://google.github.io/osv.dev/api/)
- [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages) — OSV-format reports, Apache-2.0
- [`google/osv-scanner`](https://github.com/google/osv-scanner) — Go reference implementation
- [URLhaus API](https://urlhaus.abuse.ch/api/)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
- [abuse.ch via Spamhaus (Auth-Key requirement)](https://www.spamhaus.com/data-access/abusech-api/)
- [`github/advisory-database`](https://github.com/github/advisory-database)
- [GitHub GraphQL — Security Advisories](https://docs.github.com/en/graphql/guides/using-graphql-clients)
### Distribution (HIGH confidence)
- [Homebrew Cask — Acceptable Casks](https://docs.brew.sh/Acceptable-Casks)
- [Workbrew — Homebrew 5.0.0 signing/notarization requirements](https://workbrew.com/blog/homebrew-5-0-0)
## Confidence Summary by Question
| Original question | Confidence | Notes |
|---|---|---|
| 1. Languages: Swift everywhere? | **HIGH** | Yes. Network Extension is Swift/ObjC only. Splitting CLI to Go/Rust adds friction without benefit. |
| 2. Frameworks: NE + SystemExtensions + ES + SMAppService | **HIGH** on each individually; **MEDIUM** on whether ES is required (it's *strongly recommended* for process-tree mode but not strictly mandatory) |
| 3. CLI/build: SwiftArgumentParser + XPC via SwiftyXPC | **HIGH** for ArgumentParser; **MEDIUM** for SwiftyXPC vs raw NSXPCConnection (taste, both work) |
| 4. Process-tree scoping: ES tagging > posix_spawn tricks | **MEDIUM-HIGH** — ES is the right architecture; verified by community firewall projects |
| 5. Signing/notarization: Developer ID + notarytool + Tuist | **HIGH** on signing/notarization (Apple-mandated); **MEDIUM** on Tuist vs hand-rolled .xcodeproj |
| 6. Threat-intel: native URLSession + repo-clone strategy | **MEDIUM** — no canonical Swift clients exist, but the protocols are simple JSON/CSV/GraphQL |
| 7. Logging: OSLog `Logger` | **HIGH** — Apple-recommended, integrates with System Settings privacy controls |
| 8. Testing: Swift Testing + XCTest where needed; ES + NE require integration tests | **HIGH** on Swift Testing as default; **MEDIUM** on NE testability — community consensus is "you must run on real hardware/VM with `systemextensionsctl developer on`" |
## Open Questions for Roadmap
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
