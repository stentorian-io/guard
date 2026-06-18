#!/usr/bin/env bun
import { runLinuxParity } from "../lib/docker-ci";

runLinuxParity(
  "ci-linux-e2e",
  "cargo build -p guard-cli --release; cargo test -p guard-e2e --test linux_system_install_gate --release -- --nocapture; cargo test -p guard-hook --test linux_ld_preload_smoke -- --nocapture",
);
