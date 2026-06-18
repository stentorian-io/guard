#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import { lines, output, repoRoot, run } from "../lib/command";

const messageFile = Bun.argv[2];
const message = readFileSync(messageFile, "utf8");
const subject = message.split(/\r?\n/, 1)[0] ?? "";

const red = "\x1b[0;31m";
const yellow = "\x1b[0;33m";
const bold = "\x1b[1m";
const reset = "\x1b[0m";

function reject(message: string): never {
  console.error(`${red}${bold}commit-msg: ${message}${reset}`);
  process.exit(1);
}

function warn(message: string) {
  console.error(`${yellow}commit-msg: ${message}${reset}`);
}

if (/^Co-Authored-By:/im.test(message)) {
  reject(`Co-Authored-By trailers are not allowed.
Remove the Co-Authored-By line from your commit message.`);
}

const root = repoRoot();
run("bun", [`${root}/scripts/lint/validate-conventional-subject.ts`, subject]);

const type = subject.match(/^([a-z]+)/)?.[1] ?? "";
const staged = output("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], { allowFailure: true });
const stagedFiles = lines(staged);
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

if ((type === "feat" || type === "fix") && !state.hasSrc && !state.hasUserFacingScript) {
  const suggestedTypes = [
    state.hasTest ? "test" : "",
    state.hasCi ? "ci" : "",
    state.hasDoc ? "docs" : "",
    state.hasBuild ? "chore" : "",
    "refactor",
  ].filter(Boolean).join(", ");

  reject(`'${type}' commits must change source code (.rs files) or user-facing install scripts.
Staged files are docs/tests/CI/config/internal scripts only.
Suggested types: ${suggestedTypes}`);
}

if (type === "test" && !state.hasTest && !state.hasSrc) {
  reject(`'test' commits must change test or source files.
Staged: ${stagedFiles.slice(0, 5).join("\n")}`);
}

if (type === "ci" && !state.hasCi) {
  warn("'ci' type but no .github/ files staged - double-check the type.");
}

if (type === "fix" && state.hasSrc) {
  const rsDiff = output("git", ["diff", "--cached", "-U0", "--", "*.rs"], { allowFailure: true })
    .split(/\r?\n/)
    .filter((line) => /^[+-]/.test(line))
    .filter((line) => !/^[+-][+-][+-]/.test(line))
    .filter((line) => !/^[+-]\s*\/\//.test(line))
    .filter((line) => !/^[+-]\s*$/.test(line));

  if (rsDiff.length === 0) {
    warn("All .rs changes appear to be comment-only. Consider 'docs' type instead of 'fix'.");
  }
}
