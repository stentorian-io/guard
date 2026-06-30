#!/usr/bin/env bun
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { run, sha256File, tempDir } from "../lib/command";

const OSV_ALL_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/all.zip";
const OUTPUT_FILE = "crates/guard-core/data/malicious-ossf-packages.yaml";
const benignRefHosts = new Set([
  "github.com",
  "www.github.com",
  "gitlab.com",
  "www.virustotal.com",
  "virustotal.com",
  "www.zscaler.com",
  "zscaler.com",
  "blog.phylum.io",
  "phylum.io",
  "research.jfrog.com",
  "snyk.io",
  "socket.dev",
  "www.npmjs.com",
  "npmjs.com",
  "pypi.org",
  "www.pypi.org",
  "rubygems.org",
  "crates.io",
  "pkg.go.dev",
  "hex.pm",
  "nuget.org",
  "www.nuget.org",
  "packagist.org",
  "osv.dev",
  "api.osv.dev",
  "nvd.nist.gov",
  "security.snyk.io",
  "deps.dev",
]);

type Entry = {
  matchType: "exact" | "ip";
  pattern: string;
  advisoryId: string;
  confidence: "confirmed" | "suspect";
};

const tmpdir = tempDir("stt-guard-feed");
const zipPath = join(tmpdir, "all.zip");
const advisoryDir = join(tmpdir, "advisories");

function maliciousAdvisoryFiles(path: string): string[] {
  return readdirSync(path, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.startsWith("MAL-") && entry.name.endsWith(".json"))
    .map((entry) => join(entry.parentPath, entry.name));
}

console.log("Downloading OSV.dev combined bulk archive ...");
run("curl", ["-fsSL", "--retry", "3", "--retry-delay", "5", "-o", zipPath, OSV_ALL_ZIP]);
console.log("Extracting MAL-* advisories ...");
run("unzip", ["-q", "-o", zipPath, "MAL-*.json", "-d", advisoryDir], { allowFailure: true });
rmSync(zipPath, { force: true });

const advisoryFiles = maliciousAdvisoryFiles(advisoryDir);
console.log(`Found ${advisoryFiles.length} MAL-* advisories across all ecosystems.`);
console.log("Filtering MAL-* advisories and extracting host IOCs ...");

const entriesByKey = new Map<string, Entry>();

function remember(entry: Entry) {
  if (entry.pattern.length === 0 || entry.pattern.length > 256) {
    return;
  }

  const key = `${entry.matchType}\t${entry.pattern}`;
  const existing = entriesByKey.get(key);
  if (!existing || (entry.confidence === "confirmed" && existing.confidence !== "confirmed")) {
    entriesByKey.set(key, entry);
  }
}

for (const file of advisoryFiles) {
  const advisory = await Bun.file(file).json();
  const advisoryId = advisory.id ?? "unknown";
  const iocs = advisory.database_specific?.iocs ?? {};

  for (const domain of Array.isArray(iocs.domains) ? iocs.domains : []) {
    if (typeof domain === "string") {
      remember({ matchType: "exact", pattern: domain, advisoryId, confidence: "confirmed" });
    }
  }

  for (const ip of Array.isArray(iocs.ips) ? iocs.ips : []) {
    if (typeof ip === "string") {
      remember({ matchType: "ip", pattern: ip, advisoryId, confidence: "confirmed" });
    }
  }

  for (const reference of Array.isArray(advisory.references) ? advisory.references : []) {
    if (reference?.type !== "EVIDENCE" && reference?.type !== "REPORT") {
      continue;
    }

    const url = typeof reference.url === "string" ? reference.url : "";
    const host = url.match(/^https?:\/\/([^/:]+)/)?.[1];
    if (host && !benignRefHosts.has(host)) {
      remember({ matchType: "exact", pattern: host, advisoryId, confidence: "suspect" });
    }
  }
}

const entries = [...entriesByKey.values()].sort((left, right) => left.pattern.localeCompare(right.pattern));
const confirmedCount = entries.filter((entry) => entry.confidence === "confirmed").length;
const suspectCount = entries.length - confirmedCount;

console.log(`Found ${entries.length} unique host IOCs.`);

const yaml = [
  "# Auto-generated from OSV.dev malicious-package advisories (MAL-*).",
  `# Source: ${OSV_ALL_ZIP}`,
  "# Managed by scripts/feed/update-rules.ts - do not edit manually.",
  ...entries.map((entry) => `- kind: deny
  match: ${entry.matchType}
  pattern: ${entry.pattern}
  reason: "${entry.advisoryId} supply-chain IOC (FEED)"
  confidence: ${entry.confidence}`),
  "",
].join("\n");

mkdirSync("crates/guard-core/data", { recursive: true });
writeFileSync(OUTPUT_FILE, yaml);

console.log(`Wrote ${entries.length} feed IOC entries to ${OUTPUT_FILE} (${confirmedCount} confirmed, ${suspectCount} suspect).`);
console.log(`${sha256File(OUTPUT_FILE)}  ${OUTPUT_FILE}`);
