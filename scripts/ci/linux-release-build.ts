#!/usr/bin/env bun
import { runLinuxParity } from "../lib/docker-ci";

runLinuxParity(
  "ci-linux-release-build",
  "cargo build --workspace --release; cargo build -p guard-cli -p guard-daemon -p guard-hook --release --features test-signer",
);
