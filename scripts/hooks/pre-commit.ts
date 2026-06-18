#!/usr/bin/env bun
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  branchScanBase,
  cacheHit,
  cacheMark,
  cachePrune,
  changesOnlyRepoMeta,
  linuxCiCheckFingerprint,
  linuxCiLintFingerprint,
  linuxCiReleaseBuildFingerprint,
  rustFingerprint,
  stagedMarkdownFingerprint,
} from "../lib/check-cache";
import { commandExists, fail, lines, output, repoRoot, run } from "../lib/command";

const root = repoRoot();
process.chdir(root);
process.env.PATH = `${process.env.HOME}/.cargo/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:/usr/local/bin:${process.env.PATH}`;

const green = "\x1b[0;32m";
const red = "\x1b[0;31m";
const bold = "\x1b[1m";
const reset = "\x1b[0m";

function reject(message: string): never {
  console.error(`${red}${bold}pre-commit: ${message}${reset}`);
  process.exit(1);
}

function pass(message: string) {
  console.log(`${green}✓${reset} ${message}`);
}

function warn(message: string) {
  console.log(`⚠ ${message}`);
}

function skip(message: string) {
  console.log(`${green}✓${reset} ${message} ${bold}(cached)${reset}`);
}

cachePrune();

const repoMetaOnly = changesOnlyRepoMeta("staged");

if (commandExists("bunx")) {
  const markdownFiles = output("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM", "--", "*.md"], { allowFailure: true });
  if (markdownFiles.trim().length > 0) {
    const fingerprint = stagedMarkdownFingerprint();
    if (cacheHit("pre-commit:mdlint", fingerprint)) {
      skip("markdown lint");
    } else {
      run("bunx", ["markdownlint-cli2", ...lines(markdownFiles)], {
        env: { ...process.env, TMPDIR: process.env.TMPDIR || "/private/tmp" },
      });
      cacheMark("pre-commit:mdlint", fingerprint);
      pass("markdown lint");
    }
  }
} else {
  warn("bunx not found - skipping markdown lint");
}

const workflowFiles = output("git", [
  "diff",
  "--cached",
  "--name-only",
  "--diff-filter=ACM",
  "--",
  ".github/workflows/*.yml",
  ".github/workflows/*.yaml",
], { allowFailure: true });

if (workflowFiles.trim().length > 0) {
  if (!commandExists("actionlint")) {
    reject("actionlint not found; install it locally (for example: brew install actionlint)");
  }

  run("actionlint");
  pass("GitHub Actions workflow lint");
}

const publicShellFiles = output("git", [
  "diff",
  "--cached",
  "--name-only",
  "--diff-filter=ACM",
  "--",
  "install.sh",
  "uninstall.sh",
  "tests/shell/*",
], { allowFailure: true });

const bashFixtureFiles = output("git", [
  "diff",
  "--cached",
  "--name-only",
  "--diff-filter=ACM",
  "--",
  "fixtures/vendor-ua-parser-js.sh",
], { allowFailure: true });

if (publicShellFiles.trim().length > 0 || bashFixtureFiles.trim().length > 0) {
  if (!commandExists("sh")) {
    reject("sh not found; required to lint public install scripts");
  }
  if (!commandExists("bash")) {
    reject("bash not found; required to lint fixture vendor scripts");
  }
  if (!commandExists("shellcheck")) {
    reject("shellcheck not found; install it locally with brew bundle");
  }
  if (publicShellFiles.trim().length > 0 && !commandExists("shunit2")) {
    reject("shunit2 not found; install it locally with brew bundle");
  }

  for (const file of lines(publicShellFiles)) {
    run("sh", ["-n", file]);
    run("shellcheck", ["-s", "sh", file]);
  }
  for (const file of lines(bashFixtureFiles)) {
    run("bash", ["-n", file]);
    run("shellcheck", ["-s", "bash", file]);
  }
  if (publicShellFiles.trim().length > 0) {
    run("sh", ["tests/shell/public_install_uninstall_test"]);
  }
  pass("shell lint and tests");
}

if (process.env.STT_GUARD_PRE_COMMIT_SECRET_SCAN === "1") {
  if (!commandExists("trufflehog")) {
    reject("trufflehog not found; install it or unset STT_GUARD_PRE_COMMIT_SECRET_SCAN");
  }

  run("trufflehog", ["git", `file://${root}`, "--since-commit", branchScanBase(), "--branch", "HEAD", "--only-verified", "--fail"]);
  pass("secret scan");
} else {
  warn("skipping secret scan (set STT_GUARD_PRE_COMMIT_SECRET_SCAN=1 to run)");
}

if (process.env.STT_GUARD_PRE_COMMIT_CVE_AUDIT === "1") {
  if (!commandExists("cargo-audit")) {
    reject("cargo-audit not found; install it or unset STT_GUARD_PRE_COMMIT_CVE_AUDIT");
  }

  run("cargo", ["audit"]);
  pass("dependency CVE audit");
} else {
  warn("skipping dependency CVE audit (set STT_GUARD_PRE_COMMIT_CVE_AUDIT=1 to run)");
}

if (repoMetaOnly) {
  skip("cargo check, machete, build, test (repo-meta-only change)");
  process.exit(0);
}

const rustFp = rustFingerprint();
if (cacheHit("pre-commit:rustfmt-clippy", rustFp)) {
  skip("cargo fmt and clippy");
} else {
  const scratch = mkdtempSync(join(tmpdir(), "stt-guard-pre-commit-"));
  const beforeAutofix = join(scratch, "before.patch");
  const afterAutofix = join(scratch, "after.patch");

  writeFileSync(beforeAutofix, output("git", ["diff", "--binary", "HEAD"], { allowFailure: true }));
  run("cargo", ["fmt"]);
  run("cargo", ["clippy", "--fix", "--workspace", "--all-targets", "--allow-dirty", "--allow-staged", "--quiet", "--", "-D", "warnings"]);
  writeFileSync(afterAutofix, output("git", ["diff", "--binary", "HEAD"], { allowFailure: true }));

  if (readFileSync(beforeAutofix, "utf8") !== readFileSync(afterAutofix, "utf8")) {
    rmSync(scratch, { recursive: true, force: true });
    reject("rustfmt/clippy applied fixes; review them, stage the updates, and commit again");
  }
  rmSync(scratch, { recursive: true, force: true });

  run("cargo", ["fmt", "--check"]);
  run("cargo", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]);
  cacheMark("pre-commit:rustfmt-clippy", rustFp);
  pass("cargo fmt and clippy");
}

run("bun", ["scripts/lint/test-env-vars.ts"]);
pass("test env var hygiene");

const linuxCheckFp = linuxCiCheckFingerprint();
if (cacheHit("pre-commit:linux-check", linuxCheckFp)) {
  skip("Linux check");
} else {
  run("bun", ["scripts/ci/linux-check.ts"]);
  cacheMark("pre-commit:linux-check", linuxCheckFp);
  pass("Linux check");
}

const linuxFp = linuxCiLintFingerprint();
if (cacheHit("pre-commit:linux-ci-lint", linuxFp)) {
  skip("Linux CI rustfmt/clippy");
} else {
  run("bun", ["scripts/ci/linux-lint.ts"]);
  cacheMark("pre-commit:linux-ci-lint", linuxFp);
  pass("Linux CI rustfmt/clippy");
}

if (cacheHit("pre-commit:cargo-check", rustFp)) {
  skip("cargo check");
} else {
  run("cargo", ["check", "--workspace", "--quiet"]);
  cacheMark("pre-commit:cargo-check", rustFp);
  pass("cargo check");
}

if (cacheHit("pre-commit:machete", rustFp)) {
  skip("cargo machete");
} else if (commandExists("cargo-machete")) {
  run("cargo", ["machete", "--with-metadata"]);
  cacheMark("pre-commit:machete", rustFp);
  pass("cargo machete");
} else {
  warn("cargo-machete not found - skipping (cargo install cargo-machete)");
}

if (cacheHit("pre-commit:cargo-build-release", rustFp)) {
  skip("cargo build --workspace --release");
} else {
  run("cargo", ["build", "--workspace", "--release"]);
  cacheMark("pre-commit:cargo-build-release", rustFp);
  pass("cargo build --workspace --release");
}

const linuxReleaseFp = linuxCiReleaseBuildFingerprint();
if (cacheHit("pre-commit:linux-release-build", linuxReleaseFp)) {
  skip("Linux release build");
} else {
  run("bun", ["scripts/ci/linux-release-build.ts"]);
  cacheMark("pre-commit:linux-release-build", linuxReleaseFp);
  pass("Linux release build");
}

if (cacheHit("pre-commit:cargo-test-unit", rustFp)) {
  skip("cargo test unit targets");
} else {
  run("cargo", ["test", "--workspace", "--exclude", "guard-e2e", "--lib", "--bins", "--quiet"]);
  cacheMark("pre-commit:cargo-test-unit", rustFp);
  pass("cargo test unit targets");
}

if (cacheHit("pre-commit:cargo-test-integration", rustFp)) {
  skip("cargo test integration targets");
} else {
  run("cargo", ["test", "--workspace", "--exclude", "guard-e2e", "--tests", "--quiet"]);
  cacheMark("pre-commit:cargo-test-integration", rustFp);
  pass("cargo test integration targets");
}
