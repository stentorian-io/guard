#!/usr/bin/env bun
import { appendFileSync } from "node:fs";
import { lines, output } from "../lib/command";

const eventName = process.env.GITHUB_EVENT_NAME;
const githubOutput = process.env.GITHUB_OUTPUT;

if (!eventName) {
  throw new Error("GITHUB_EVENT_NAME is required");
}

if (!githubOutput) {
  throw new Error("GITHUB_OUTPUT is required");
}

function writeOutputs(values: Record<string, string | boolean>) {
  appendFileSync(githubOutput!, Object.entries(values).map(([key, value]) => `${key}=${value}\n`).join(""));
}

if (eventName === "schedule") {
  writeOutputs({
    code: false,
    lockfile: true,
    markdown: false,
    tooling: false,
    hot_path_benchmark: false,
    base: "",
    head: "",
    is_pr: false,
  });
  process.exit(0);
}

const baseRef = Bun.argv[2] ?? "upstream/main";
const changed = output("git", ["diff", "--name-only", `${baseRef}...HEAD`]);
console.log(`Changed files:\n${changed}`);

let code = false;
let lockfile = false;
let markdown = false;
let tooling = false;
let hotPathBenchmark = false;

for (const path of lines(changed)) {
  if (
    path.endsWith(".rs")
    || path.endsWith("/Cargo.toml")
    || path === "Cargo.toml"
    || path.endsWith("/Cargo.lock")
    || path === "Cargo.lock"
    || path === "rust-toolchain.toml"
    || path.startsWith("crates/guard-e2e/fixtures/")
    || path.startsWith("crates/guard-e2e/harness/")
    || path.startsWith("crates/guard-core/data/")
  ) {
    code = true;
    hotPathBenchmark = true;
  }

  if (path === "scripts/bench/hot-path.ts") {
    hotPathBenchmark = true;
  }

  if (
    path.startsWith("scripts/")
    || path.startsWith("fixtures/")
    || path.startsWith("tests/shell/")
    || path === "install.sh"
    || path === "uninstall.sh"
    || path.startsWith(".github/workflows/")
    || path.startsWith(".github/actions/")
  ) {
    tooling = true;
  }

  if (path.endsWith("/Cargo.toml") || path === "Cargo.toml" || path.endsWith("/Cargo.lock") || path === "Cargo.lock" || path === "rust-toolchain.toml") {
    lockfile = true;
  }

  if (path.endsWith(".md")) {
    markdown = true;
  }
}

const base = output("git", ["merge-base", baseRef, "HEAD"]).trim();
const head = output("git", ["rev-parse", "HEAD"]).trim();

writeOutputs({
  code,
  lockfile,
  markdown,
  tooling,
  hot_path_benchmark: hotPathBenchmark,
  base,
  head,
  is_pr: true,
});

console.log(`Secret scan range: ${base}..${head}`);
