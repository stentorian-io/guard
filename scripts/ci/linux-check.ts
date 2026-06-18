#!/usr/bin/env bun
import { runLinuxParity } from "../lib/docker-ci";

runLinuxParity(
  "ci-linux-check",
  "actual=$(shasum -a 256 crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz | awk '{print $1}'); pinned=$(grep -E '^EXPECTED_OUTPUT_SHA256=\"[a-f0-9]{64}\"$' fixtures/vendor-ua-parser-js.sh | sed -E 's/^EXPECTED_OUTPUT_SHA256=\"([a-f0-9]{64})\"$/\\1/'); test \"$actual\" = \"$pinned\"; cargo check -p guard-os -p guard-watchdog --quiet; cargo check -p guard-hook -p guard-daemon -p guard-cli --quiet",
);
