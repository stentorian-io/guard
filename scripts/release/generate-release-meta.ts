#!/usr/bin/env bun
import { commandExists, output } from "../lib/command";

const newTag = Bun.argv[2];
if (!newTag) {
  console.error("usage: generate-release-meta.ts <new-tag> [previous-tag]");
  process.exit(1);
}

const version = newTag.replace(/^v/, "");
const previousTag = Bun.argv[3] ?? output("git", ["describe", "--tags", "--abbrev=0", `${newTag}^`], { allowFailure: true }).trim();
const range = `${previousTag ? `${previousTag}..` : ""}${newTag}`;

let denyRuleCount = 0;
if (previousTag) {
  const diff = output("git", ["diff", previousTag, newTag, "--", "crates/guard-core/data/malicious-*.yaml"], { allowFailure: true });
  denyRuleCount = diff.split(/\r?\n/).filter((line) => line.startsWith("+  - ")).length;
}

let securityFixes = false;
const tagExists = output("git", ["rev-parse", "--verify", "--quiet", `${newTag}^{commit}`], { allowFailure: true }).trim().length > 0;
if (tagExists) {
  securityFixes = /fix!?: security:/i.test(output("git", ["log", "--format=%s", range], { allowFailure: true }));
}

const severity = denyRuleCount > 0 || securityFixes ? "critical" : "informational";
let summary = "";

if (commandExists("git-cliff") && previousTag) {
  summary = output("git", ["cliff", range, "--strip", "all"], { allowFailure: true })
    .split(/\r?\n/)
    .slice(0, 20)
    .filter((line) => line.startsWith("- "))
    .slice(0, 3)
    .map((line) => line.replace(/^- /, ""))
    .join("; ");
} else {
  const commitCount = output("git", ["rev-list", "--count", range], { allowFailure: true }).trim() || "0";
  summary = `${commitCount} commits since ${previousTag || "initial"}`;
}

if (summary.length === 0) {
  summary = `Release ${version}`;
}

const publishedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const changelogUrl = `https://github.com/stentorian-io/guard/releases/tag/${newTag}`;

console.log(JSON.stringify({
  version,
  severity,
  summary,
  deny_rule_count: denyRuleCount,
  security_fixes: securityFixes,
  published_at: publishedAt,
  changelog_url: changelogUrl,
}, null, 2));
