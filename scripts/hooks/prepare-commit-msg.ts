#!/usr/bin/env bun
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { lines, output } from "../lib/command";

const messageFile = Bun.argv[2];
const messageSource = Bun.argv[3] ?? "";

if (messageSource === "merge" || messageSource === "squash") {
  process.exit(0);
}

const stagedFiles = lines(output("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], { allowFailure: true }));
if (stagedFiles.length === 0) {
  process.exit(0);
}

const state = {
  hasSrc: false,
  hasTest: false,
  hasCi: false,
  hasDoc: false,
  hasBuild: false,
  hasUserFacingScript: false,
};

for (const file of stagedFiles) {
  if (file === "install.sh" || file === "uninstall.sh") {
    state.hasUserFacingScript = true;
  } else if (file.startsWith(".github/workflows/") || file.startsWith(".github/actions/")) {
    state.hasCi = true;
  } else if (file.startsWith("crates/guard-e2e/tests/") || file.includes("/tests/") || file.startsWith("crates/guard-e2e/harness/") || file.startsWith("crates/guard-e2e/fixtures/")) {
    state.hasTest = true;
  } else if (file === "Cargo.toml" || file.endsWith("/Cargo.toml") || file === "Cargo.lock" || file === "rust-toolchain.toml") {
    state.hasBuild = true;
  } else if (file.endsWith(".rs")) {
    state.hasSrc = true;
  } else if (file.startsWith("docs/") || file.endsWith(".md")) {
    state.hasDoc = true;
  } else if (["cliff.toml", "Brewfile", ".gitignore"].includes(file) || file.startsWith(".markdownlint") || file.startsWith("scripts/")) {
    state.hasBuild = true;
  }
}

function inferType() {
  if (state.hasSrc && !state.hasTest && !state.hasCi) {
    return "feat or fix";
  }
  if (state.hasUserFacingScript && !state.hasTest && !state.hasCi) {
    return "feat or fix";
  }
  if (state.hasTest && !state.hasSrc) {
    return "test";
  }
  if (state.hasCi && !state.hasSrc) {
    return "ci";
  }
  if (state.hasDoc && !state.hasSrc && !state.hasTest && !state.hasCi) {
    return "docs";
  }
  if (state.hasBuild && !state.hasSrc && !state.hasTest && !state.hasCi) {
    return "chore or build";
  }
  if (state.hasSrc && state.hasTest) {
    return "feat or fix (with tests)";
  }

  return "unclear";
}

const inferred = inferType();
const message = readFileSync(messageFile, "utf8");
const firstLine = message.split(/\r?\n/, 1)[0] ?? "";
const currentType = firstLine.match(/^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\(.+\))?!?: .+/)?.[1] ?? "";

if (currentType.length > 0) {
  let rewrite = "";

  if (/^(feat|fix)$/.test(currentType) && state.hasDoc && !state.hasSrc && !state.hasTest && !state.hasCi) {
    rewrite = "docs";
  }
  if (/^(feat|fix)$/.test(currentType) && state.hasTest && !state.hasSrc && !state.hasCi && !state.hasDoc) {
    rewrite = "test";
  }
  if (/^(feat|fix)$/.test(currentType) && state.hasCi && !state.hasSrc && !state.hasTest && !state.hasDoc) {
    rewrite = "ci";
  }
  if (/^(feat|fix)$/.test(currentType) && state.hasBuild && !state.hasSrc && !state.hasUserFacingScript && !state.hasTest && !state.hasCi && !state.hasDoc) {
    rewrite = "chore";
  }
  if (rewrite.length > 0 && rewrite !== currentType) {
    writeFileSync(messageFile, message.replace(new RegExp(`^${currentType}`), rewrite));
    console.error(`prepare-commit-msg: rewritten type '${currentType}' -> '${rewrite}' (staged files: ${inferred})`);
  }
}

if (messageSource !== "message" || currentType.length === 0) {
  const changelogNote = inferred === "test" || inferred === "ci" || inferred === "docs" || inferred === "chore or build"
    ? "(will NOT appear in changelog)"
    : "(will appear in changelog)";

  appendFileSync(messageFile, `
# -- Commit type guidance --------------------------------------
# Staged files suggest: ${inferred} ${changelogNote}
#
# Changelog types: feat, fix, perf
# Internal types:  docs, test, refactor, chore, build, ci
#
# Rules enforced by commit-msg hook:
#   feat/fix -> must change source code (.rs) or user-facing install scripts
#   test     -> must change test files
#   ci       -> should change .github/ files
#   subject  -> uses <type>: <description>, with no component/scope
#   subject  -> starts lowercase and does not end with a period
# --------------------------------------------------------------
`);
}
