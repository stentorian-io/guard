#!/usr/bin/env bun
import { appendFileSync, chmodSync, copyFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { fail, output, run, sha256File } from "../lib/command";

const githubOutput = process.env.GITHUB_OUTPUT;
if (!githubOutput) {
  throw new Error("GITHUB_OUTPUT is required");
}

const version = Bun.argv[2];
if (!version) {
  fail("ci-package-release-tarballs", "usage: ci-package-release-tarballs.ts <version>");
}

writeFileSync("artifacts/checksums.txt", "");

for (const entry of readdirSync("artifacts", { withFileTypes: true })) {
  if (!entry.isDirectory() || !entry.name.startsWith("guard-")) {
    continue;
  }

  const target = entry.name.replace(/^guard-/, "");
  const targetDir = `artifacts/${entry.name}`;
  copyFileSync("artifacts/release-meta.json", `${targetDir}/release-meta.json`);

  for (const binary of ["stt-guard", "stt-guard-daemon", "stt-guard-watchdog"]) {
    chmodSync(`${targetDir}/${binary}`, 0o755);
  }

  const tarball = `artifacts/guard-${version}-${target}.tar.gz`;
  run("tar", [
    "-C",
    targetDir,
    "-czf",
    tarball,
    "stt-guard",
    "stt-guard-daemon",
    "stt-guard-watchdog",
    "stt-guard-hook.dylib",
    "release-meta.json",
  ]);

  const sha = sha256File(tarball);
  appendFileSync("artifacts/checksums.txt", `${sha}  ${basename(tarball)}\n`);

  if (target === "aarch64-apple-darwin") {
    appendFileSync(githubOutput, `arm64_tarball=${tarball}\narm64_sha256=${sha}\n`);
  } else if (target === "x86_64-apple-darwin") {
    appendFileSync(githubOutput, `x86_64_tarball=${tarball}\nx86_64_sha256=${sha}\n`);
  } else {
    fail("ci-package-release-tarballs", `unexpected target: ${target}`);
  }
}

void output;
