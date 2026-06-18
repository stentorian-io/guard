#!/usr/bin/env bun
import { lines, output, run } from "../lib/command";

const baseRef = Bun.argv[2] ?? "origin/main";
const target = "crates/guard-core/data/malicious-ossf-packages.yaml";
const changedFiles = lines(output("git", ["diff", "--name-only", `${baseRef}...HEAD`]));

if (changedFiles.length === 0) {
  console.error(`::error::Feed update branch has no changes relative to ${baseRef}`);
  process.exit(1);
}

const unexpectedFiles = changedFiles.filter((file) => file !== target);
if (unexpectedFiles.length > 0) {
  console.error(`::error::Feed update branch changed files outside ${target}`);
  console.error(unexpectedFiles.join("\n"));
  process.exit(1);
}

if (!changedFiles.includes(target)) {
  console.error(`::error::Feed update branch did not change ${target}`);
  process.exit(1);
}

run("cargo", ["test", "-p", "guard-daemon", "--test", "curated_yaml_tests"]);
