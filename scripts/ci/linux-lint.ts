#!/usr/bin/env bun
import { runLinuxParity } from "../lib/docker-ci";

runLinuxParity(
  "ci-linux-lint",
  "cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings",
);
