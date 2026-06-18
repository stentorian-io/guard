import { existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureDir, lines, output, readIfExists, repoRoot, sha256Text } from "./command";

const CACHE_MAX_AGE_HOURS = 24;

function gitDir() {
  return output("git", ["rev-parse", "--git-dir"], { allowFailure: true }).trim();
}

function cacheDir() {
  return join(gitDir(), "check-cache");
}

function cacheKey(phase: string, fingerprint: string) {
  return sha256Text(`${phase}:${fingerprint}`);
}

export function cacheHit(phase: string, fingerprint: string) {
  ensureDir(cacheDir());

  return existsSync(join(cacheDir(), cacheKey(phase, fingerprint)));
}

export function cacheMark(phase: string, fingerprint: string) {
  ensureDir(cacheDir());
  writeFileSync(join(cacheDir(), cacheKey(phase, fingerprint)), `${Math.floor(Date.now() / 1000)}\n`);
}

export function cachePrune() {
  ensureDir(cacheDir());

  const cutoff = Math.floor(Date.now() / 1000) - CACHE_MAX_AGE_HOURS * 3600;
  for (const entry of readdirSync(cacheDir())) {
    const path = join(cacheDir(), entry);
    if (!statSync(path).isFile()) {
      continue;
    }

    const timestamp = Number(readFileSync(path, "utf8").trim() || "0");
    if (Number.isFinite(timestamp) && timestamp < cutoff) {
      rmSync(path, { force: true });
    }
  }
}

function headSha() {
  return output("git", ["rev-parse", "HEAD"], { allowFailure: true }).trim() || "no-head";
}

function diffIndex(paths: string[]) {
  return output("git", ["diff-index", "HEAD", "--", ...paths], { allowFailure: true });
}

export function rustFingerprint() {
  return sha256Text(`${headSha()}\n${diffIndex(["*.rs", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"])}`);
}

export function fixtureFingerprint() {
  const fixture = "crates/guard-e2e/fixtures/ua-parser-js-0.7.29-sanitized/ua-parser-js-0.7.29-sanitized.tgz";
  const vendor = "fixtures/vendor-ua-parser-js.sh";

  return sha256Text(`${headSha()}\n${readIfExists(fixture)}${readIfExists(vendor)}`);
}

export function linuxCiLintFingerprint() {
  return sha256Text(`${rustFingerprint()}\n${diffIndex([
    "scripts/hooks/pre-commit.ts",
    "scripts/hooks/pre-push.ts",
    "scripts/ci/linux-check.ts",
    "scripts/ci/linux-lint.ts",
    "scripts/ci/linux-release-build.ts",
    "scripts/lib/check-cache.ts",
    "scripts/lint/test-env-vars.ts",
    ".github/workflows/ci.yml",
    ".github/actions/",
  ])}`);
}

export function linuxCiCheckFingerprint() {
  return sha256Text(`${rustFingerprint()}\n${fixtureFingerprint()}\n${diffIndex([
    "scripts/hooks/pre-commit.ts",
    "scripts/ci/linux-check.ts",
    "scripts/ci/verify-sanitized-fixture.ts",
    "scripts/lib/check-cache.ts",
    ".github/workflows/ci.yml",
    ".github/actions/",
  ])}`);
}

export function linuxCiReleaseBuildFingerprint() {
  return sha256Text(`${rustFingerprint()}\n${diffIndex([
    "scripts/hooks/pre-commit.ts",
    "scripts/ci/linux-release-build.ts",
    "scripts/lib/check-cache.ts",
    ".github/workflows/ci.yml",
    ".github/actions/",
  ])}`);
}

export function stagedMarkdownFingerprint() {
  const files = lines(output("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM", "--", "*.md"], { allowFailure: true })).sort();
  const diffs = files.map((file) => output("git", ["diff", "--cached", "--", file], { allowFailure: true })).join("\n");

  return sha256Text(`${headSha()}\n${diffs}`);
}

export function changesAffectE2eFiles(files: string) {
  return lines(files).some((file) => {
    return file.endsWith(".rs")
      || file === "Cargo.toml"
      || file === "Cargo.lock"
      || file.endsWith("/Cargo.toml")
      || file.endsWith("/Cargo.lock")
      || file === "rust-toolchain.toml"
      || file.startsWith("crates/guard-e2e/fixtures/")
      || file.startsWith("crates/guard-e2e/harness/")
      || file.startsWith("crates/guard-core/data/");
  });
}

export function changesOnlyRepoMeta(mode: "staged" | "all") {
  const changed = mode === "staged"
    ? output("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMRD"], { allowFailure: true })
    : output("git", ["diff-index", "--name-only", "HEAD"], { allowFailure: true });

  const files = lines(changed);
  if (files.length === 0) {
    return false;
  }

  return files.every((file) => {
    return file.endsWith(".md")
      || file.startsWith("LICENSE")
      || file.startsWith("SECURITY")
      || file === ".gitignore"
      || file === ".gitattributes"
      || file.startsWith(".github/workflows/") && file.endsWith(".yml")
      || file === "Brewfile"
      || file === "cliff.toml"
      || file.startsWith(".markdownlint")
      || file === ".editorconfig";
  });
}

export function branchScanBase() {
  return output("git", ["merge-base", "--fork-point", "@{upstream}", "HEAD"], { allowFailure: true }).trim()
    || output("git", ["merge-base", "origin/main", "HEAD"], { allowFailure: true }).trim()
    || output("git", ["merge-base", "main", "HEAD"], { allowFailure: true }).trim();
}

export function workspaceRoot() {
  return repoRoot();
}
