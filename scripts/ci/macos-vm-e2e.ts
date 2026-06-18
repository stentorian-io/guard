#!/usr/bin/env bun
import { openSync } from "node:fs";
import { spawn } from "node:child_process";
import { output, repoRoot, run } from "../lib/command";

const root = repoRoot();
process.chdir(root);

const baseImage = process.env.STT_GUARD_MACOS_VM_BASE ?? "ghcr.io/cirruslabs/macos-tahoe-base:latest";
const baseName = process.env.STT_GUARD_MACOS_VM_BASE_NAME ?? "stt-guard-macos-base";
const vmName = process.env.STT_GUARD_MACOS_VM_NAME ?? `stt-guard-e2e-${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}-${process.pid}`;
const vmUser = process.env.STT_GUARD_MACOS_VM_USER ?? "admin";
const vmPassword = process.env.STT_GUARD_MACOS_VM_PASSWORD ?? "admin";
const remoteRoot = process.env.STT_GUARD_MACOS_VM_REMOTE_ROOT ?? `/Users/${vmUser}/stt-guard`;
const vmGraphics = process.env.STT_GUARD_MACOS_VM_GRAPHICS ?? "1";
const sshOptions = [
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "PubkeyAuthentication=no",
  "-o", "PreferredAuthentications=password",
  "-o", "NumberOfPasswordPrompts=1",
  "-o", "ConnectTimeout=10",
  "-o", "ServerAliveInterval=15",
];

function fail(message: string): never {
  console.error(`ci-macos-vm-e2e: ${message}`);
  process.exit(1);
}

function needCommand(command: string) {
  if (run("sh", ["-c", `command -v "$1" >/dev/null 2>&1`, "sh", command], { quiet: true, allowFailure: true }).status !== 0) {
    fail(`${command} is required`);
  }
}

function vmExists(name: string) {
  const list = output("tart", ["list"], { allowFailure: true });

  return list.split(/\r?\n/).slice(1).some((line) => line.trim().split(/\s+/)[1] === name);
}

function ensureBaseImage() {
  if (vmExists(baseName)) {
    return;
  }

  console.log(`ci-macos-vm-e2e: cloning base image ${baseImage} -> ${baseName}`);
  run("tart", ["clone", baseImage, baseName]);
}

function sshGuest(ip: string, command: string, input?: string) {
  return run("sshpass", ["-p", vmPassword, "ssh", ...sshOptions, `${vmUser}@${ip}`, command], {
    input,
    allowFailure: false,
  });
}

function rsyncToGuest(ip: string) {
  run("rsync", [
    "-az",
    "--delete",
    "-e",
    `sshpass -p '${vmPassword}' ssh ${sshOptions.join(" ")}`,
    "--exclude",
    ".git",
    "--exclude",
    "target",
    "--exclude",
    ".gsd",
    `${root}/`,
    `${vmUser}@${ip}:${remoteRoot}/`,
  ]);
}

function cleanup() {
  if (vmExists(vmName)) {
    run("tart", ["stop", vmName], { quiet: true, allowFailure: true });
    run("tart", ["delete", vmName], { quiet: true, allowFailure: true });
  }
}

async function waitForIp() {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const ip = output("tart", ["ip", vmName], { allowFailure: true }).trim();
    if (ip.length > 0) {
      return ip;
    }
    await Bun.sleep(3_000);
  }

  fail("timed out waiting for VM IP");
}

async function waitForSsh(ip: string) {
  const deadline = Date.now() + 180_000;
  let successfulLogins = 0;

  while (Date.now() < deadline) {
    const result = run("sshpass", ["-p", vmPassword, "ssh", ...sshOptions, `${vmUser}@${ip}`, "true"], { quiet: true, allowFailure: true });
    if (result.status === 0) {
      successfulLogins += 1;
      if (successfulLogins >= 3) {
        return;
      }
    } else {
      successfulLogins = 0;
    }

    await Bun.sleep(3_000);
  }

  fail(`timed out waiting for SSH on ${ip}`);
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function configureGuest(ip: string) {
  const script = `set -euo pipefail
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo -S tee /etc/sudoers.d/stt-guard-ci-nopasswd >/dev/null
sudo chmod 440 /etc/sudoers.d/stt-guard-ci-nopasswd
sudo -n true
if command -v security >/dev/null; then
  security unlock-keychain -p "$STT_GUARD_VM_PASSWORD" "$HOME/Library/Keychains/login.keychain-db" || true
  security set-keychain-settings -lut 21600 "$HOME/Library/Keychains/login.keychain-db" || true
fi
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
if ! command -v bun >/dev/null; then
  curl -fsSL https://bun.sh/install | bash
fi
export PATH="$HOME/.bun/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
rustc --version
cargo --version
bun --version
`;

  sshGuest(ip, `cat > /tmp/stt-guard-guest-setup.sh && STT_GUARD_VM_PASSWORD=${shellQuote(vmPassword)} bash /tmp/stt-guard-guest-setup.sh`, script);
}

function runGuestE2e(ip: string) {
  const script = `set -euo pipefail
cd "$STT_GUARD_REMOTE_ROOT"
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
export PATH="$HOME/.bun/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
cargo build --workspace --release
cargo test -p guard-e2e --test hardened_install_health --release -- --nocapture 2>&1 | tee /tmp/stt-guard-hardened-install-health.log
if grep -q '^SKIP:' /tmp/stt-guard-hardened-install-health.log; then
  echo "hardened_install_health reported SKIP; this VM cannot provide no-skip privileged validation" >&2
  exit 2
fi
cargo build -p guard-cli -p guard-daemon -p guard-hook --release --features test-signer
cargo test -p guard-e2e --features test-signer --test ua_parser_js_demo --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test workers_dev_validation --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test failure_modes_corrupt_snapshot --release -- --nocapture
cargo test -p guard-e2e --features test-signer --test failure_modes_hardened_exec --release -- --nocapture
`;

  const remoteRootQuoted = shellQuote(remoteRoot);
  const runCommand = vmGraphics === "1"
    ? `cat > /tmp/stt-guard-run-e2e.sh && chmod +x /tmp/stt-guard-run-e2e.sh && sudo launchctl asuser "$(id -u)" sudo -u '${vmUser}' env STT_GUARD_REMOTE_ROOT=${remoteRootQuoted} bash /tmp/stt-guard-run-e2e.sh`
    : `cat > /tmp/stt-guard-run-e2e.sh && STT_GUARD_REMOTE_ROOT=${remoteRootQuoted} bash /tmp/stt-guard-run-e2e.sh`;

  sshGuest(ip, runCommand, script);
}

for (const command of ["tart", "sshpass", "rsync"]) {
  needCommand(command);
}

process.on("exit", cleanup);
process.on("SIGINT", () => {
  cleanup();
  process.exit(130);
});

ensureBaseImage();

console.log(`ci-macos-vm-e2e: cloning disposable VM ${baseName} -> ${vmName}`);
run("tart", ["clone", baseName, vmName]);

console.log(`ci-macos-vm-e2e: starting ${vmName}`);
const logPath = `/tmp/${vmName}.log`;
const tartArgs = vmGraphics === "1" ? ["run", vmName] : ["run", "--no-graphics", vmName];
const logFd = openSync(logPath, "a");
const child = spawn("tart", tartArgs, {
  detached: true,
  stdio: ["ignore", logFd, logFd],
});
child.unref();
void child;

const ip = await waitForIp();
console.log(`ci-macos-vm-e2e: VM IP is ${ip}`);
await waitForSsh(ip);
configureGuest(ip);

console.log("ci-macos-vm-e2e: syncing repository to guest");
rsyncToGuest(ip);

console.log("ci-macos-vm-e2e: running macOS E2E suite with privileged install health");
runGuestE2e(ip);

console.log("ci-macos-vm-e2e: complete");
