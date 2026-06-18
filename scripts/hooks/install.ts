#!/usr/bin/env bun
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { output } from "../lib/command";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = output("git", ["-C", scriptDir, "rev-parse", "--show-toplevel"]).trim();
const hooksPath = output("git", ["-C", repoRoot, "rev-parse", "--git-path", "hooks"]).trim();
const hooksDir = isAbsolute(hooksPath) ? hooksPath : join(repoRoot, hooksPath);
mkdirSync(hooksDir, { recursive: true });
rmSync(join(hooksDir, "lib"), { recursive: true, force: true });
cpSync(join(repoRoot, "scripts", "lib"), join(hooksDir, "lib"), { recursive: true });

function installHook(name: string) {
  const source = join(scriptDir, `${name}.ts`);
  const destination = join(hooksDir, name);

  if (!existsSync(source)) {
    console.error(`error: scripts/hooks/${name}.ts not found`);
    process.exit(1);
  }

  const hook = readFileSync(source, "utf8").replaceAll('from "../lib/', 'from "./lib/');
  writeFileSync(destination, hook);
  chmodSync(destination, 0o755);
  console.log(`${name} hook installed -> .git/hooks/${name}`);
}

for (const hook of ["prepare-commit-msg", "commit-msg", "pre-commit", "pre-push"]) {
  installHook(hook);
}
