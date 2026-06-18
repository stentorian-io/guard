#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { fail, sha256File } from "../lib/command";

const fixture = "crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz";
if (!existsSync(fixture)) {
  fail("ci-verify-sanitized-fixture", "FATAL: sanitized fixture missing");
}

const actual = sha256File(fixture);
console.log(`Fixture SHA-256: ${actual}`);

const vendor = readFileSync("fixtures/vendor-ua-parser-js.sh", "utf8");
const matches = [...vendor.matchAll(/^EXPECTED_OUTPUT_SHA256="([a-f0-9]{64})"$/gm)];
if (matches.length !== 1) {
  fail("ci-verify-sanitized-fixture", `FATAL: expected exactly one EXPECTED_OUTPUT_SHA256 line in fixtures/vendor-ua-parser-js.sh, found ${matches.length}`);
}

const pinned = matches[0][1];
if (actual !== pinned) {
  console.error("FATAL: fixture hash mismatch; fixture drifted from script pin");
  console.error(`  script pin: ${pinned}`);
  console.error(`  on-disk:    ${actual}`);
  process.exit(1);
}

console.log("Fixture hash matches script pin.");
