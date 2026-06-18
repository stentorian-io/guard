#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import { fail, lines, output, repoRoot } from "../lib/command";

process.chdir(repoRoot());

const files = lines(output("find", ["crates", "-path", "crates/*/src/*", "-name", "*.rs", "-type", "f"]));
let errors = 0;

for (const file of files) {
  if (file.startsWith("crates/guard-e2e/")) {
    continue;
  }

  const fullContent = readFileSync(file, "utf8");
  const cfgTestIndex = fullContent.search(/#\[cfg\(test\)\]/);
  const productionContent = cfgTestIndex >= 0 ? fullContent.slice(0, cfgTestIndex) : fullContent;
  const matches = productionContent
    .split(/\r?\n/)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => line.includes("STT_GUARD_TEST_"))
    .filter(({ line }) => !file.startsWith("crates/guard-hook/src/") || !line.includes("STT_GUARD_TEST_MARKER"));

  if (matches.length > 0) {
    console.log(`ERROR: STT_GUARD_TEST_ in production code: ${file}`);
    for (const match of matches) {
      console.log(`  ${match.number}:${match.line}`);
    }
    errors += 1;
  }
}

if (errors > 0) {
  fail("lint-test-env-vars", `
FAIL: ${errors} file(s) reference STT_GUARD_TEST_* outside test code.
Test env vars must only appear in crates/guard-e2e/, #[cfg(test)] modules,
or as STT_GUARD_TEST_MARKER in guard-hook (allowed by design).`);
}

console.log("OK: no STT_GUARD_TEST_* references in production source.");
