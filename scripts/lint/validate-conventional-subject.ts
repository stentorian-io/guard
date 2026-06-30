#!/usr/bin/env bun
import { fail } from "../lib/command";

const subject = Bun.argv[2] ?? "";

function reject(message: string): never {
  fail("validate-conventional-subject", message);
}

if (subject.length === 0) {
  reject("subject is required");
}

const scopedMatch = subject.match(/^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)\(([^)]+)\)!?: /);
if (scopedMatch) {
  reject(`components are not allowed in commit subjects.
Use '${scopedMatch[1]}: ...' not '${scopedMatch[1]}(${scopedMatch[2]}): ...'
Got: ${subject}`);
}

const match = subject.match(/^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)!?: (.+)$/);
if (!match) {
  reject(`subject does not follow Conventional Commits.
Expected: <type>: <description>
Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
Got: ${subject}`);
}

const type = match[1];
const description = match[2];

if (/^[A-Z]/.test(description)) {
  reject(`description must start with a lowercase letter.
Got: ${subject}`);
}

if (/\.$/.test(description)) {
  reject(`description must not end with a period.
Got: ${subject}`);
}
