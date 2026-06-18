#!/usr/bin/env bun
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { output, run, tempDir } from "../lib/command";

const CACHE_HIT_BUDGET_DEFAULT_NS = 100_000;

function usage() {
  console.log(`Usage:
  ./scripts/bench/hot-path.ts [options]

Options:
  --dry-run                              Validate output parsing with synthetic samples.
  --cache-hit-only                       Run only the deterministic cache-hit microbench.
  --enforce-cache-hit-budget             Fail if cache-hit p99 exceeds the budget.
  --cache-hit-budget-ns <ns>             Override the script's cache-hit p99 budget.
  --github-action-benchmark-json <path>  Write customSmallerIsBetter JSON for github-action-benchmark.
  -h, --help                             Show this help.`);
}

function extractP99(text: string) {
  return text.match(/p99=([0-9]+)/)?.[1] ?? "unknown";
}

function fmtNs(value: string) {
  return value === "unknown" ? value : `${value}ns`;
}

function runCaptured(command: string, args: string[], outputPath: string) {
  const result = Bun.spawnSync([command, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const stdout = new TextDecoder().decode(result.stdout);
  const stderr = new TextDecoder().decode(result.stderr);
  process.stdout.write(stdout);
  process.stderr.write(stderr);
  writeFileSync(outputPath, `${stdout}${stderr}`);

  if (result.exitCode !== 0) {
    process.exit(result.exitCode);
  }
}

const args = [...Bun.argv.slice(2)];
if (args[0] === "--dry-run") {
  const sampleCacheHit = "cache_hit/decide_for_sockaddr p50=541ns p95=541ns p99=541ns p99.9=541ns max=541ns";
  const sampleLiveWrap = "LIVE_WRAP_NS p50=12345 p95=23456 p99=34567 p999=45678 max=56789";
  const cacheHitP99 = extractP99(sampleCacheHit);
  const liveWrapP99 = extractP99(sampleLiveWrap);

  if (cacheHitP99 === "unknown") {
    console.error("dry-run FAIL: cache-hit regex did not match the synthetic sample.");
    process.exit(1);
  }

  if (liveWrapP99 === "unknown") {
    console.error("dry-run FAIL: live-wrap regex did not match the synthetic sample.");
    process.exit(1);
  }

  console.log("dry-run: ok");
  console.log(`  cache-hit p99 extracted from synthetic sample: ${cacheHitP99}`);
  console.log(`  live-wrap p99 extracted from synthetic sample: ${liveWrapP99}`);
  console.log("  the runner is wired correctly; capture the real numbers via:");
  console.log("    ./scripts/bench/hot-path.ts    (no flags) on the reference Apple Silicon machine");
  process.exit(0);
}

let cacheHitOnly = false;
let enforceCacheHitBudget = false;
let cacheHitBudgetNs = CACHE_HIT_BUDGET_DEFAULT_NS;
let cacheHitBudgetSource = "scripts/bench/hot-path.ts CACHE_HIT_BUDGET_DEFAULT_NS";
let githubActionBenchmarkJson = "";

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];

  if (arg === "--cache-hit-only") {
    cacheHitOnly = true;
  } else if (arg === "--enforce-cache-hit-budget") {
    enforceCacheHitBudget = true;
  } else if (arg === "--cache-hit-budget-ns") {
    const value = args[++index];
    if (!value || !/^[0-9]+$/.test(value)) {
      console.error("--cache-hit-budget-ns must be an integer number of nanoseconds");
      process.exit(2);
    }
    cacheHitBudgetNs = Number(value);
    cacheHitBudgetSource = "command line";
  } else if (arg === "--github-action-benchmark-json") {
    const value = args[++index];
    if (!value) {
      console.error("--github-action-benchmark-json requires a path");
      process.exit(2);
    }
    githubActionBenchmarkJson = value;
  } else if (arg === "-h" || arg === "--help") {
    usage();
    process.exit(0);
  } else {
    console.error(`unknown option: ${arg}`);
    usage();
    process.exit(2);
  }
}

const gitSha = output("git", ["rev-parse", "--short", "HEAD"]).trim();
const isoDate = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const macModel = output("sysctl", ["-n", "hw.model"], { allowFailure: true }).trim() || "unknown";
const memBytes = Number(output("sysctl", ["-n", "hw.memsize"], { allowFailure: true }).trim() || "0");
const memGb = Math.floor(memBytes / 1_073_741_824);
const macosVersion = output("sw_vers", ["-productVersion"], { allowFailure: true }).trim() || "unknown";
const rustcVersion = output("rustc", ["--version"], { allowFailure: true }).trim() || "unknown";
const scratch = tempDir("bench-hot-path");

console.error("## bench-hot-path: building workspace --release ...");
run("cargo", ["build", "--workspace", "--release"]);

console.error("## bench-hot-path: cache-hit (binding number) ...");
const cacheHitOutput = join(scratch, "bench-cache-hit.out");
runCaptured("cargo", ["bench", "-p", "guard-bench", "--bench", "cache_hit_hot_path"], cacheHitOutput);

const liveWrapOutput = join(scratch, "bench-live-wrap.out");
if (!cacheHitOnly) {
  console.error("## bench-hot-path: live-wrap (context number) ...");
  runCaptured("cargo", ["test", "-p", "guard-e2e", "--release", "--test", "bench_hot_path_e2e", "--", "--ignored", "--nocapture"], liveWrapOutput);
} else {
  console.error("## bench-hot-path: live-wrap skipped (--cache-hit-only)");
  writeFileSync(liveWrapOutput, "");
}

const cacheHitP99 = extractP99(readFileSync(cacheHitOutput, "utf8"));
const liveWrapP99 = extractP99(readFileSync(liveWrapOutput, "utf8"));

if (cacheHitP99 === "unknown") {
  console.error("bench-hot-path: could not extract cache-hit p99 from benchmark output");
  process.exit(1);
}

if (enforceCacheHitBudget && Number(cacheHitP99) > cacheHitBudgetNs) {
  console.error(`bench-hot-path: cache-hit p99 ${cacheHitP99}ns exceeds ${cacheHitBudgetNs}ns budget from ${cacheHitBudgetSource}`);
  console.error("bench-hot-path: if this regression is intentional, update CACHE_HIT_BUDGET_DEFAULT_NS near the top of scripts/bench/hot-path.ts and explain the new budget in the PR.");
  process.exit(1);
}

if (githubActionBenchmarkJson) {
  mkdirSync(dirname(githubActionBenchmarkJson), { recursive: true });
  const benchmarkRows = [
    {
      name: "cache-hit decide_for_sockaddr p99",
      unit: "ns",
      value: Number(cacheHitP99),
      extra: `budget: ${cacheHitBudgetNs}ns\nbudget source: ${cacheHitBudgetSource}\ngit SHA: ${gitSha}\nmacOS: ${macosVersion}\nrustc: ${rustcVersion}`,
    },
  ];

  if (liveWrapP99 !== "unknown") {
    benchmarkRows.push({
      name: "live-wrap npmjs connect p99",
      unit: "ns",
      value: Number(liveWrapP99),
      extra: `context benchmark; no fixed budget\ngit SHA: ${gitSha}\nmacOS: ${macosVersion}\nrustc: ${rustcVersion}`,
    });
  }

  writeFileSync(githubActionBenchmarkJson, `${JSON.stringify(benchmarkRows, null, 2)}\n`);
}

console.log(`
## Bench Summary

Benchmark results:

| machine | RAM | macOS | rustc | git SHA | date (UTC) | cache-hit p99 | live-wrap p99 |
|---------|-----|-------|-------|---------|------------|----------------|----------------|
| ${macModel} | ${memGb} GB | ${macosVersion} | ${rustcVersion} | ${gitSha} | ${isoDate} | ${fmtNs(cacheHitP99)} | ${fmtNs(liveWrapP99)} |

Methodology: criterion 0.8.2, hdrhistogram 7.5.4. Sample size and warm-up are
criterion defaults (100 samples, 3s warm-up, 5s measurement_time, 95% CI on the
mean). p99 is computed via hdrhistogram::value_at_quantile(0.99) on small
batch-average per-call nanoseconds captured inside b.iter_custom(...), which
keeps hosted-runner scheduler stalls from dominating the cache-hit metric.

Reproduce: ./scripts/bench/hot-path.ts on any Apple Silicon Mac with the
workspace built.`);
