# Synthetic ua-parser-js@0.7.29 mock — Stentorian Guard VAL-01 fixture

This directory contains a **synthetic mock** of the historically compromised
npm package `ua-parser-js@0.7.29`. The historical 2021 supply-chain attack
is the reference; **this fixture contains no real malicious bytes**.

It exists for **Stentorian Guard's VAL-01 validation test only**. The committed
`ua-parser-js-0.7.29-sanitized.tgz` is a deterministic build product of
`tools/vendor-ua-parser-js.sh` and is byte-identical across hosts.

## Provenance — Why a Synthetic Mock?

The original Plan 05-01 specified vendor-time **reconstruction** of the
ua-parser-js@0.7.29 tarball from public github commits on
`github.com/faisalman/ua-parser-js`:

- `90fb09d8` — primary malicious commit (preinstall.js)
- `8742775c` — related malicious commit
- `e09c01ed` — related malicious commit

Those commits were **scrubbed from the upstream repository** in early 2026.
They are no longer publicly accessible (404 on github; no Wayback Machine
snapshot). The original recipe is now unrunnable.

CONTEXT D-06 ("Synthetic mock is NOT used for v0.1") explicitly named the
synthetic-mock variant as the legitimate escape-hatch alternative if
upstream fidelity later became unattainable. **That escape hatch is now
invoked**, with orchestrator-confirmed user decision recorded in the
Plan 05-01 summary.

## Sanitization Manifest

What is **NOT** in this fixture (vs. the historical 2021 ua-parser-js@0.7.29):

| Component                                | Present here? |
|------------------------------------------|---------------|
| Real C2 hostname (`citationsherbe.at`, `xmr-eu1.nanopool.org`, etc.) | **No** |
| Real C2 IPs (`159.148.186.228`, `194.76.225.46`, etc.) | **No** |
| XMRig (Monero miner binary)              | **No** |
| Linux exfil keylogger / `sdd.bdvl` payload | **No** |
| Obfuscated postinstall payload           | **No** |
| Windows `preinstall.bat` / Linux `preinstall.sh` from upstream | **No** |
| Real `ua-parser-js` library code         | **No** (empty `index.js` stub) |

What **IS** in this fixture:

| Component                                | Description |
|------------------------------------------|---------------|
| `package/package.json`                   | Synthetic, declares `preinstall: "node preinstall.js"` and `version: "0.7.29"` |
| `package/preinstall.js`                  | Synthetic — opens TCP to `c2-sink.test.invalid:443`, prints a marker line, exits 0 |
| `package/index.js`                       | Empty stub — `module.exports = {};` |

The **only behavior VAL-01 asserts on** is the postinstall opening an
outbound TCP connection. The synthetic preinstall reproduces exactly that
shape and nothing else.

## Pinned SHA-256

```
9398ea5503135f17bc0c424e6373ddce7c0e113d23577a136638dd7ddcdce984
```

Embedded in `tools/vendor-ua-parser-js.sh` as `EXPECTED_OUTPUT_SHA256`.
The script verifies on every run; drift triggers an abort.

CI does **not** run the vendoring script. CI verifies the committed
tarball against this pin (per CONTEXT D-02 / D-15).

## Reconstruction Recipe

The synthetic fixture is rebuildable byte-identically from
`tools/vendor-ua-parser-js.sh`:

```sh
bash tools/vendor-ua-parser-js.sh
```

The script writes a `package/` tree under `mktemp -d`, normalizes mtimes
via `touch -t 202001010000.00`, packs with `bsdtar --uid 0 --gid 0
--uname '' --gname ''`, sorts entries with `LC_ALL=C sort`, and
compresses with `gzip -n`. Output is byte-identical across hosts.

If a future revision changes the synthetic source, refresh the pin with:

```sh
bash tools/vendor-ua-parser-js.sh --update-pin
bash tools/vendor-ua-parser-js.sh   # verify
```

Both this README and the script must be updated together; fixture changes should
receive explicit maintainer review.

## Triple-Layer Safety (per CONTEXT D-02)

1. **Stentorian Guard does its job.** The validation test passes only when
   Stentorian Guard's dylib blocks the postinstall's `connect()` to
   `c2-sink.test.invalid`. The thing under test IS the safety guarantee.

2. **No real C2.** `c2-sink.test.invalid` is in the IETF-reserved
   `.invalid` TLD — it cannot resolve, ever. Even if Stentorian Guard fails,
   the network stack receives a name that DNS will refuse.

3. **Sandboxed test HOME.** The VAL-01 test sets `HOME=$(mktemp -d)`
   with empty `.ssh/`, `.aws/`, `.npmrc`, no env-var secrets (Plan
   05-02 helper). Even a complete enforcement failure would find
   nothing to exfiltrate.

## Threat Model

- **Drive-by PR mutation:** Any change to this directory requires explicit
  maintainer review.
- **Fixture drift:** `EXPECTED_OUTPUT_SHA256` in the script aborts on
  any unintentional rebuild that produces different bytes.
- **No extraction risk:** The synthetic builder constructs the tarball
  from scratch — there is no untrusted-tarball extraction step, so
  zip-slip is not in scope. (If a future revision re-introduces
  extraction, see RESEARCH §V12 for the required `--no-same-owner
  --no-same-permissions` guards.)
