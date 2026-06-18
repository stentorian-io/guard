#!/usr/bin/env bun
import { cacheHit, cacheMark, cachePrune, changesAffectE2eFiles, linuxCiLintFingerprint, branchScanBase } from "../lib/check-cache";
import { commandExists, fail, lines, output, repoRoot, run } from "../lib/command";

const root = repoRoot();
process.chdir(root);
process.env.PATH = `${process.env.HOME}/.cargo/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:/usr/local/bin:${process.env.PATH}`;

const green = "\x1b[0;32m";
const yellow = "\x1b[0;33m";
const bold = "\x1b[1m";
const reset = "\x1b[0m";

function reject(message: string): never {
  console.error(`\x1b[0;31m${bold}pre-push: ${message}${reset}`);
  process.exit(1);
}

function pass(message: string) {
  console.log(`${green}✓${reset} ${message}`);
}

function warn(message: string) {
  console.log(`${yellow}⚠${reset} ${message}`);
}

function changedFilesForPush(remoteName: string, pushRefs: string) {
  const zeroSha = "0000000000000000000000000000000000000000";
  const changed = new Set<string>();

  for (const line of lines(pushRefs)) {
    const [localRef, localSha, , remoteSha] = line.split(/\s+/);
    if (!localRef || localSha === zeroSha) {
      continue;
    }

    const baseRef = remoteSha === zeroSha
      ? output("git", ["merge-base", localSha, `${remoteName}/main`], { allowFailure: true }).trim()
        || output("git", ["merge-base", localSha, "origin/main"], { allowFailure: true }).trim()
        || output("git", ["merge-base", localSha, "main"], { allowFailure: true }).trim()
        || output("git", ["rev-parse", `${localSha}^`], { allowFailure: true }).trim()
      : remoteSha;

    for (const file of lines(output("git", ["diff", "--name-only", baseRef, localSha], { allowFailure: true }))) {
      changed.add(file);
    }
  }

  return [...changed].sort().join("\n");
}

function runHotPathBenchmark() {
  if (output("uname", ["-s"]).trim() !== "Darwin") {
    warn("skipping hot-path benchmark (macOS-only)");
    return;
  }

  run("mkdir", ["-p", "target/bench-hot-path"]);
  run("bun", [
    "scripts/bench/hot-path.ts",
    "--cache-hit-only",
    "--enforce-cache-hit-budget",
    "--github-action-benchmark-json",
    "target/bench-hot-path/pre-push-github-action-benchmark.json",
  ]);
  pass("hot-path benchmark");
}

const pushRefs = await new Response(Bun.stdin.stream()).text();
const pushChangedFiles = changedFilesForPush(Bun.argv[2] ?? "origin", pushRefs);

run("bun", ["scripts/lint/test-env-vars.ts"]);
pass("test env var hygiene");

if (process.env.STT_GUARD_PRE_PUSH_SECRET_SCAN === "1") {
  if (!commandExists("trufflehog")) {
    reject("trufflehog not found; install it or unset STT_GUARD_PRE_PUSH_SECRET_SCAN");
  }

  run("trufflehog", ["git", `file://${root}`, "--since-commit", branchScanBase(), "--branch", "HEAD", "--only-verified", "--fail"]);
  pass("secret scan");
} else {
  warn("skipping secret scan (set STT_GUARD_PRE_PUSH_SECRET_SCAN=1 to run)");
}

if (process.env.STT_GUARD_PRE_PUSH_CVE_AUDIT === "1") {
  if (!commandExists("cargo-audit")) {
    reject("cargo-audit not found; install it or unset STT_GUARD_PRE_PUSH_CVE_AUDIT");
  }

  run("cargo", ["audit"]);
  pass("dependency CVE audit");
} else {
  warn("skipping dependency CVE audit (set STT_GUARD_PRE_PUSH_CVE_AUDIT=1 to run)");
}

if (pushChangedFiles.length === 0) {
  pass("skipping pre-push runtime checks (no pushed file changes detected)");
  process.exit(0);
}

if (pushChangedFiles.length > 0 && !changesAffectE2eFiles(pushChangedFiles)) {
  pass("skipping pre-push runtime checks (no E2E-relevant files changed)");
  process.exit(0);
}

cachePrune();
const linuxFp = linuxCiLintFingerprint();
if (cacheHit("pre-push:linux-ci-lint", linuxFp) || cacheHit("pre-commit:linux-ci-lint", linuxFp)) {
  pass("Linux CI rustfmt/clippy (cached)");
} else {
  run("bun", ["scripts/ci/linux-lint.ts"]);
  cacheMark("pre-push:linux-ci-lint", linuxFp);
  pass("Linux CI rustfmt/clippy");
}

run("bun", ["scripts/ci/linux-e2e.ts"]);
pass("Linux E2E parity");

run("bun", ["scripts/ci/macos-vm-e2e.ts"]);
pass("macOS VM E2E parity");

runHotPathBenchmark();

console.log(`\n${green}${bold}All pre-push E2E checks passed.${reset}`);
