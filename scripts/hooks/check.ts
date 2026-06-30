#!/usr/bin/env bun
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { output, repoRoot } from "../lib/command";

const root = repoRoot();
const requiredHooks = ["prepare-commit-msg", "commit-msg", "pre-commit", "pre-push"];

function gitConfig(key: string) {
  return output("git", ["config", "--get", key], { allowFailure: true }).trim();
}

function fail(message: string): never {
  console.error(`setup: ${message}`);
  process.exit(1);
}

function check(message: string, ok: boolean) {
  if (!ok) {
    fail(message);
  }

  console.log(`✓ ${message}`);
}

const gitHooksPath = output("git", ["rev-parse", "--git-path", "hooks"]).trim();
const hooksDir = isAbsolute(gitHooksPath) ? gitHooksPath : join(root, gitHooksPath);
const signingKey = gitConfig("user.signingkey");
const signingKeyPath = isAbsolute(signingKey) ? signingKey : resolve(root, signingKey);
const signingKeyContents = existsSync(signingKeyPath) ? readFileSync(signingKeyPath, "utf8").trim() : "";
const allowedSigners = gitConfig("gpg.ssh.allowedSignersFile");
const allowedSignersPath = isAbsolute(allowedSigners) ? allowedSigners : resolve(root, allowedSigners);

check("git user.name is set", gitConfig("user.name").length > 0);
check("git user.email is set", gitConfig("user.email").length > 0);
check("git gpg.format is ssh", gitConfig("gpg.format") === "ssh");
check("git commit.gpgsign is true", gitConfig("commit.gpgsign") === "true");
check("git tag.gpgSign is true", gitConfig("tag.gpgSign") === "true");
check("git user.signingkey points at an SSH public key", /^(ssh|ecdsa)-/.test(signingKeyContents));
check("git gpg.ssh.allowedSignersFile exists", existsSync(allowedSignersPath));

for (const hook of requiredHooks) {
  const hookPath = join(hooksDir, hook);
  const executable = existsSync(hookPath) && (statSync(hookPath).mode & 0o111) !== 0;
  const source = readFileSync(join(root, "scripts", "hooks", `${hook}.ts`), "utf8")
    .replaceAll('from "../lib/', 'from "./lib/');
  const installed = existsSync(hookPath) ? readFileSync(hookPath, "utf8") : "";

  check(`${hook} hook is installed`, executable);
  check(`${hook} hook is current`, installed === source);
}
