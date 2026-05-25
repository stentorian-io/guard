# Post-Quantum Cryptography Readiness

## Audience And Use

This audit is for maintainers who add or review cryptographic behavior in Stentorian Guard. After reading it, a maintainer should be able to decide whether a new signing, key-storage, transport-security, hashing, randomness, or certificate-validation change is acceptable for v1 or needs a migration plan first.

## Summary

Stentorian Guard currently uses cryptography for local integrity and authenticity, not for long-term confidentiality. The security-critical signing path is ML-DSA-65 over canonical CBOR payloads, with SHA-256 used for digests and public-key fingerprints. Because the project has not shipped a stable release yet, v1 chooses a post-quantum local signature profile now instead of shipping a classical profile and migrating later.

macOS does not currently provide non-exportable Secure Enclave ML-DSA keys. The tradeoff is explicit: v1 prefers post-quantum signature security for project-owned artifacts, stores the private key as a user-owned 0600 file, and keeps private key material out of daemon-writable state.

## Inventory

### Dependency Inventory

Direct cryptographic dependencies are limited to:

- `pqcrypto-mldsa` and `pqcrypto-traits` for ML-DSA-65 signature generation and verification.
- `sha2` for SHA-256 digests and public key fingerprints.
- `getrandom` for run identifiers and snapshot publication nonces.
- macOS Security.framework for code-sign validation.

Indirect crypto dependencies come from those direct choices: `pqcrypto-internals`, `digest`, `crypto-common`, `block-buffer`, and `generic-array`.

No `rustls`, `native-tls`, `openssl`, `ring`, `webpki`, X.509 parser, or certificate-validation crate is currently in the normal workspace dependency graph.

### Usage Inventory

| Area | Current dependency or platform primitive | Protected property | Post-quantum exposure |
| --- | --- | --- | --- |
| User rule, management action, and snapshot signatures | ML-DSA-65 in production and test-signer builds | Local policy authenticity and daemon-forgery resistance | PQ-native. Key storage is software-backed until supported platforms expose non-exportable PQ keys. |
| Signature verification and public key encoding | PQClean ML-DSA-65 via `pqcrypto-mldsa` | Signature correctness and stable serialization | PQ-native. |
| Snapshot and manifest digests | SHA-256 | File integrity binding before decoding and mapping | Acceptable. SHA-256 still provides a conservative integrity margin for this use. |
| Public key fingerprints | SHA-256 over public key bytes | Trust-root lookup and mismatch detection | Acceptable. This is an identifier, not the only proof of authenticity. |
| Trusted signer manifest | Root-owned public signer registry plus daemon mirror of public metadata | Trust root separation from daemon-writable state | No secret material. Production signer entries are ML-DSA public keys. |
| Random run identifiers and snapshot nonces | OS randomness through `getrandom` | Collision resistance and unpredictability for per-run names and publication paths | Acceptable. No PQ-specific weakness identified. |
| IPC transport | Unix domain socket, CBOR frames, kernel audit token peer identity, OS code-sign validity checks | Same-host peer authentication and message framing | No TLS or public-key encryption. PQ dependency is delegated to macOS code-signing policy and Apple platform roots. |
| Hook snapshot loading | Manifest path confinement, digest verification, ML-DSA snapshot signature verification, trusted signer lookup | Fail-closed local policy loading | PQ-native for production snapshots. The fail-closed design remains correct. |
| Embedded curated feeds | YAML data compiled into the binary | Built-in policy integrity through source control, CI, release, local snapshot signing, and install ownership | Current embedded data has no separate feed signature. Future online or out-of-band feed distribution must not rely on classical-only signatures. |
| Lockfile registry extraction | Structured parsing of package-manager lockfiles for registry hostnames | Destination allowlist derivation from project-local metadata | Not a TLS or certificate-validation decision. A malicious lockfile can influence allowed hosts by design and should remain constrained by signed snapshot publication. |
| TLS and certificate validation | No in-process TLS client stack for feed or package downloads | Package-manager downloads are outside Guard's crypto boundary | No direct PQ TLS migration exists in the current code. Future network fetchers must define TLS and feed-signature requirements together. |
| Logs, snapshots, and state | Plain local files with ownership isolation | Local auditability and policy state | No long-term encrypted data was identified. There is no store-now-decrypt-later confidentiality exposure in current protected data. |

## Risk Classification

| Risk | Classification | Rationale |
| --- | --- | --- |
| Local rule and snapshot forgery after a future quantum break of P-256 | Low | Project-owned policy signatures use ML-DSA-65. No P-256 signing path remains. |
| Security feed or release metadata signed only with ECDSA P-256 | High for new designs | Remote distribution creates reusable artifacts and broader replay/downgrade risk. Starting classical-only would create avoidable migration debt. |
| SHA-256 digest and fingerprint use | Low | SHA-256 remains appropriate for artifact integrity and identifiers. Do not truncate below 256 bits without a separate analysis. |
| Lack of in-process TLS implementation today | Low | Guard does not fetch package data itself. This becomes high if a future feed updater downloads policy data without independent signed metadata. |
| Long-term confidentiality compromise | Informational | The current design does not encrypt retained secrets or promise secrecy for data that could be collected now and decrypted later. |

## Recommended Defaults

### v1 Local Integrity Profile

Use this local-integrity default:

- Algorithm: ML-DSA-65 with SHA-256 fingerprints and payload digests.
- Key storage: user-owned 0600 private key file, never copied into daemon-writable state.
- Accepted production signer kind: `software-ml-dsa`.
- Serialization: canonical CBOR payloads with explicit schema versions.
- Verification: reject unsupported schema versions, unsupported schemes, untrusted signers, malformed public keys, malformed signatures, payload hash mismatches, and signature mismatches.
- Failure mode: fail closed for snapshot loading, policy resolution, and persistent-rule verification.

The explicit test-simulator profile also uses ML-DSA-65 so CI exercises the same primitive without depending on production key enrollment. Production policy must still reject the `test-simulator` signer kind.

### New Remote Trust Profile

For security feed distribution, release metadata, cross-machine policy import, or any artifact expected to be verified by many machines over time, use a hybrid profile:

- Primary post-quantum signature: ML-DSA-65 or the current NIST-standardized equivalent at the time of implementation.
- Classical companion signature: ECDSA P-256 with SHA-256 or Ed25519, chosen for platform and dependency fit.
- Acceptance rule: require both signatures during the initial hybrid period.
- Key separation: feed, release, and local policy keys must be separate trust roots.
- Metadata: include artifact type, schema version, policy version, creation time, expiration time, signing profile, signer identity, key identifier, monotonic sequence, and content digest.
- Replay protection: reject stale sequence numbers for a given trust root and reject expired metadata.
- Downgrade protection: signed metadata must name the required signing profile so attackers cannot strip the PQ signature and present a classical-only variant.

## Migration Guidance

No stable release has shipped with local Secure Enclave signers, so there is no user-data migration requirement for v1. Pre-release development state can be reinitialized with `sudo stt-guard init`.

Before adding remote feed distribution or release signing, introduce a versioned `SigningProfile` concept so signatures are not identified only by free-form strings. The first profiles should cover the current local ML-DSA integrity profile and the new hybrid remote-trust profile.

When platform hardware supports non-exportable PQ or hybrid keys, add them as a new local profile instead of changing the meaning of the current ML-DSA scheme. Existing manifests and snapshots should remain verifiable under their original profile until their normal lifecycle expires.

If a future migration needs to replace ML-DSA-65 for local policy, ship it as an additive verifier first:

1. Accept both the current profile and the replacement profile.
2. Enroll replacement signers and publish manifests that identify both keys.
3. Prefer new signatures from the replacement profile.
4. Warn on old-profile-only state.
5. Remove old-profile acceptance only after an explicit compatibility window.

## Acceptance Criteria For Future Crypto Changes

Every change that adds or changes cryptography must answer these questions in the design or PR:

- What property is protected: authenticity, integrity, confidentiality, freshness, replay resistance, downgrade resistance, or identity?
- Is the protected data local and short-lived, or remotely distributed and long-lived?
- Which signing profile is used, and why is a non-PQ or classical-only profile acceptable if one is chosen?
- Where is private key material generated, stored, used, rotated, and destroyed?
- Is the private key exportable? If platform support forces software key storage, what ownership and permission boundaries keep the daemon from forging artifacts?
- What schema fields bind artifact type, version, signer identity, creation time, expiration time, and content digest?
- How are replay and downgrade attempts detected?
- What is the fail-closed behavior if verification, certificate validation, randomness, or key access fails?
- Which dependencies implement the primitive, and are they already in the workspace?
- What narrow tests prove malformed, stale, downgraded, unsigned, and wrongly signed artifacts are rejected?

## Follow-Up Issues

1. Add a versioned signing-profile enum and replace free-form scheme strings at new crypto boundaries.
2. Design the hybrid post-quantum signing format for security feed distribution and release metadata.
3. Add replay and downgrade metadata requirements to the planned feed distribution model.
4. Document key-separation rules for local policy, feed distribution, release metadata, and future hardware-backed PQ signing providers.
5. Add a CI guard that inventories cryptographic dependencies and flags newly introduced TLS, certificate, random, hash, or signing crates for explicit review.
6. Decide whether lockfile-derived registry hosts should distinguish `http` from `https` before future policy UX relies on transport-security semantics.

## Non-Findings

- No current in-process TLS stack or certificate store was found.
- No long-term encrypted local secret store was found.
- No project-owned P-256 signer remains.
- No runtime feed downloader was found in the current implementation; curated feed data is embedded at build time.
