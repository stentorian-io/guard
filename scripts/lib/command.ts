import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";

export type RunOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
  quiet?: boolean;
  allowFailure?: boolean;
};

export function fail(prefix: string, message: string, code = 1): never {
  console.error(`${prefix}: ${message}`);
  process.exit(code);
}

export function run(command: string, args: string[] = [], options: RunOptions = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    input: options.input,
    stdio: options.quiet ? ["pipe", "pipe", "pipe"] : ["inherit", "inherit", "inherit"],
    encoding: "utf8",
  });

  if (result.error && !options.allowFailure) {
    fail(command, result.error.message);
  }

  if ((result.status ?? 1) !== 0 && !options.allowFailure) {
    process.exit(result.status ?? 1);
  }

  return result;
}

export function output(command: string, args: string[] = [], options: RunOptions = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    input: options.input,
    stdio: ["pipe", "pipe", "pipe"],
    encoding: "utf8",
  });

  if ((result.status ?? 1) !== 0 && !options.allowFailure) {
    const stderr = result.stderr.trim();
    fail(command, stderr || `${command} ${args.join(" ")} failed`);
  }

  return result.stdout;
}

export function commandExists(command: string) {
  return run("sh", ["-c", `command -v "$1" >/dev/null 2>&1`, "sh", command], { quiet: true, allowFailure: true }).status === 0;
}

export function repoRoot() {
  return output("git", ["rev-parse", "--show-toplevel"]).trim();
}

export function sha256Text(text: string) {
  return createHash("sha256").update(text).digest("hex");
}

export function sha256File(path: string) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function ensureDir(path: string) {
  mkdirSync(path, { recursive: true });
}

export function writeFileEnsuringDir(path: string, contents: string) {
  ensureDir(dirname(path));
  writeFileSync(path, contents);
}

export function removePath(path: string) {
  rmSync(path, { recursive: true, force: true });
}

export function tempDir(prefix: string) {
  const base = process.env.TMPDIR || "/tmp";
  const path = output("mktemp", ["-d", join(base, `${prefix}.XXXXXX`)]).trim();

  process.on("exit", () => {
    removePath(path);
  });

  return path;
}

export function readIfExists(path: string) {
  return existsSync(path) ? readFileSync(path, "utf8") : "";
}

export function lines(text: string) {
  return text.split(/\r?\n/).filter((line) => line.length > 0);
}
