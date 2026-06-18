#!/usr/bin/env bun
import { fail } from "../lib/command";

const subject = Bun.argv[2] ?? "";

function reject(message: string): never {
  fail("validate-conventional-subject", message);
}

if (subject.length === 0) {
  reject("subject is required");
}

const match = subject.match(/^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(([^)]+)\))?!?: (.+)$/);
if (!match) {
  reject(`subject does not follow Conventional Commits.
Expected: <type>(<scope>): <description>
Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
Got: ${subject}`);
}

const type = match[1];
const scope = match[3] ?? "";
const description = match[4];

if (type === "docs") {
  const allowedScopes = new Set(["readme", "llm", "bench", "man", "help", "install"]);

  if (scope.length === 0) {
    reject(`'docs' subjects require an explicit scope.
Allowed: docs(readme), docs(llm), docs(bench), docs(man), docs(help), docs(install)
Got: ${subject}`);
  }

  if (!allowedScopes.has(scope)) {
    reject(`docs(${scope}) is not a recognized scope.
Allowed: readme, llm, bench, man, help, install
Changelog scopes: man, help, install`);
  }
}

if (type === "ci" && scope.length > 0) {
  reject(`Scopes are not allowed for the 'ci' type. Use 'ci: ...' not 'ci(${scope}): ...'`);
}

if (/^[A-Z]/.test(description)) {
  reject(`description must start with a lowercase letter.
Got: ${subject}`);
}

if (/\.$/.test(description)) {
  reject(`description must not end with a period.
Got: ${subject}`);
}
