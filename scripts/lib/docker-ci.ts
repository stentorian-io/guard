import { mkdirSync } from "node:fs";
import { commandExists, fail, repoRoot, run } from "./command";

const IMAGE = "rust:1.96.0-bookworm";
const CACHE_ROOT = "/private/tmp/stt-guard-docker";

export function runLinuxParity(prefix: string, command: string) {
  const root = repoRoot();
  process.chdir(root);

  if (!commandExists("docker")) {
    fail(prefix, `docker is required for ${prefix.replace(/^ci-linux-/, "Linux ")} parity`);
  }

  const dockerInfo = run("docker", ["info"], { quiet: true, allowFailure: true });
  if (dockerInfo.status !== 0) {
    fail(prefix, "docker is not running");
  }

  const cargoRegistryCache = `${CACHE_ROOT}/cargo-registry`;
  const rustupCache = `${CACHE_ROOT}/rustup`;
  const targetCache = `${CACHE_ROOT}/target`;
  mkdirSync(cargoRegistryCache, { recursive: true });
  mkdirSync(rustupCache, { recursive: true });
  mkdirSync(targetCache, { recursive: true });

  run("docker", [
    "run",
    "--rm",
    "-v",
    `${root}:/work`,
    "-v",
    `${cargoRegistryCache}:/usr/local/cargo/registry`,
    "-v",
    `${rustupCache}:/usr/local/rustup`,
    "-v",
    `${targetCache}:/target`,
    "-w",
    "/work",
    IMAGE,
    "bash",
    "-lc",
    `set -euo pipefail; export PATH=/usr/local/cargo/bin:$PATH; export CARGO_TARGET_DIR=/target; ${command}`,
  ]);
}
