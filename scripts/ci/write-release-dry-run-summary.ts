#!/usr/bin/env bun
import { appendFileSync, readFileSync } from "node:fs";
import { fail, output } from "../lib/command";

const githubStepSummary = process.env.GITHUB_STEP_SUMMARY;
if (!githubStepSummary) {
  throw new Error("GITHUB_STEP_SUMMARY is required");
}

const tag = Bun.argv[2];
if (!tag) {
  fail("ci-write-release-dry-run-summary", "usage: ci-write-release-dry-run-summary.ts <tag>");
}

const artifacts = output("ls", ["-lh", "artifacts/"]);
const releaseMetadata = readFileSync("artifacts/release-meta.json", "utf8");

appendFileSync(githubStepSummary, `## Dry Run Summary
**Tag:** ${tag}
**Artifacts:**
${artifacts}
**Release metadata:**
${releaseMetadata}
`);
