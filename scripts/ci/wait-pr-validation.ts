#!/usr/bin/env bun
import { output } from "../lib/command";

const repository = process.env.GITHUB_REPOSITORY;
const headSha = process.env.HEAD_SHA;

if (!repository) {
  throw new Error("GITHUB_REPOSITORY is required");
}

if (!headSha) {
  throw new Error("HEAD_SHA is required");
}

for (let attempt = 0; attempt < 60; attempt += 1) {
  const runJsonText = output("gh", [
    "run",
    "list",
    "--repo",
    repository,
    "--workflow",
    "pr-validation.yml",
    "--event",
    "pull_request",
    "--commit",
    headSha,
    "--limit",
    "1",
    "--json",
    "databaseId,status,conclusion,url",
    "--jq",
    ".[0] // empty",
  ], { allowFailure: true }).trim();

  if (runJsonText.length === 0) {
    console.log(`Waiting for PR validation run for ${headSha}...`);
    await Bun.sleep(10_000);
    continue;
  }

  const runJson = JSON.parse(runJsonText);
  const conclusion = runJson.conclusion ?? "";
  console.log(`PR validation: status=${runJson.status} conclusion=${conclusion || "pending"} url=${runJson.url}`);

  if (runJson.status === "completed" && conclusion === "success") {
    process.exit(0);
  }

  if (runJson.status === "completed") {
    console.error(`::error::PR validation did not pass for ${headSha}: ${conclusion}`);
    process.exit(1);
  }

  await Bun.sleep(10_000);
}

console.error(`::error::Timed out waiting for PR validation for ${headSha}`);
process.exit(1);
