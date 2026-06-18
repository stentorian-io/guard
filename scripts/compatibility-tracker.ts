#!/usr/bin/env bun

const ISSUE_1 = "https://github.com/stentorian-io/guard/issues/1";
const ISSUE_2 = "https://github.com/stentorian-io/guard/issues/2";

type Args = {
  manifest: string;
  offline: boolean;
  createIssues: boolean;
  repo?: string;
};

type Manifest = {
  schema_version: number;
  sources: Source[];
  labels?: Labels;
  cpu_architectures: CpuArchitecture[];
  operating_systems: OperatingSystems;
  toolchains: Toolchains;
};

type Labels = {
  base?: string[];
};

type Source = {
  id: string;
  category: string;
  url?: string;
  products?: LifecycleProduct[];
};

type LifecycleProduct = {
  id: string;
  category: string;
  url: string;
};

type CpuArchitecture = {
  id: string;
  aliases?: string[];
};

type OperatingSystems = {
  macos: MacosSupport;
  linux: LinuxSupport;
};

type MacosSupport = {
  supported?: CycleEntry[];
  best_effort?: CycleEntry[];
  tracked?: CycleEntry[];
};

type CycleEntry = {
  cycle: string;
};

type LinuxSupport = {
  kernel_series?: string[];
};

type Toolchains = {
  xcode: ToolchainCycles;
  rust: RustToolchain;
  llvm: ToolchainCycles;
};

type ToolchainCycles = {
  tracked_cycles?: string[];
};

type RustToolchain = {
  minimum: string;
  pinned: string;
  tracked_releases?: string[];
  tracked_targets?: string[];
};

type ReviewEntry = {
  id: string;
  title: string;
  labels: string[];
  sourceId: string;
  body: string;
};

function main(): void {
  run(parseArgs(Bun.argv.slice(2))).catch((error) => {
    console.error(`compatibility tracker failed: ${error.message}`);
    process.exit(1);
  });
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    manifest: "compatibility-matrix.yaml",
    offline: false,
    createIssues: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    switch (arg) {
      case "--manifest":
        args.manifest = requiredArg(argv, (index += 1), "--manifest");
        break;
      case "--offline":
        args.offline = true;
        break;
      case "--create-issues":
        args.createIssues = true;
        break;
      case "--repo":
        args.repo = requiredArg(argv, (index += 1), "--repo");
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  return args;
}

function requiredArg(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }

  return value;
}

async function run(args: Args): Promise<void> {
  const manifestText = await Bun.file(args.manifest).text();
  const manifest = (Bun as any).YAML.parse(manifestText) as Manifest;
  const repo = args.repo ?? process.env.GITHUB_REPOSITORY;

  validateManifest(manifest);

  if (args.offline) {
    console.log(`Validated ${args.manifest}; offline mode did not fetch sources.`);
    return;
  }

  const knownIds = knownIdsForManifest(manifest);
  const knownAliases = knownAliasesForManifest(manifest);
  const reviewEntries = (await observedEntries(manifest)).filter(
    (entry) => !knownEntry(entry, knownIds, knownAliases),
  );

  reportEntries(reviewEntries);

  if (args.createIssues) {
    createReviewIssues(manifest, reviewEntries, repo);
    return;
  }

  if (reviewEntries.length > 0) {
    process.exit(2);
  }
}

function validateManifest(manifest: Manifest): void {
  if (manifest.schema_version !== 1) {
    throw new Error(`unsupported compatibility manifest schema ${manifest.schema_version}`);
  }

  const sourceIds = new Set<string>();
  const duplicateSourceIds: string[] = [];

  for (const source of manifest.sources) {
    if (source.id.trim() === "") {
      throw new Error("source id must not be empty");
    }

    if (sourceIds.has(source.id)) {
      duplicateSourceIds.push(source.id);
    }
    sourceIds.add(source.id);

    const products = source.products ?? [];
    if (!source.url && products.length === 0) {
      throw new Error(`source ${source.id} needs url or products`);
    }

    if (source.url && products.length > 0) {
      throw new Error(`source ${source.id} must use either url or products, not both`);
    }
  }

  if (duplicateSourceIds.length > 0) {
    throw new Error(`duplicate source ids: ${duplicateSourceIds.join(", ")}`);
  }
}

async function observedEntries(manifest: Manifest): Promise<ReviewEntry[]> {
  const entries: ReviewEntry[] = [];
  let sourceSuccesses = 0;

  for (const source of manifest.sources) {
    try {
      entries.push(...(await fetchSourceEntries(source)));
      sourceSuccesses += 1;
    } catch (error) {
      console.error(`warning: ${source.id} failed: ${errorMessage(error)}`);
    }
  }

  if (sourceSuccesses === 0) {
    throw new Error("all compatibility sources failed");
  }

  return entries;
}

async function fetchSourceEntries(source: Source): Promise<ReviewEntry[]> {
  switch (source.id) {
    case "apple-xnu-machine":
      return xnuCpuEntries(source);
    case "llvm-triple-definitions":
      return llvmArchEntries(source);
    case "rust-platform-support":
      return rustTargetEntries(source);
    case "endoflife-lifecycle":
      return lifecycleEntries(source);
    case "apple-developer-releases":
      return appleXcodeEntries(source);
    case "github-llvm-releases":
      return llvmReleaseEntries(source);
    default:
      console.error(`warning: no fetcher for ${source.id}`);
      return [];
  }
}

async function lifecycleEntries(source: Source): Promise<ReviewEntry[]> {
  const entries: ReviewEntry[] = [];

  for (const product of source.products ?? []) {
    const payload = await fetchJson(product.url);
    if (!Array.isArray(payload)) {
      throw new Error(`${product.id} did not return a JSON array`);
    }

    for (const cycle of lifecycleCycles(product, payload)) {
      const cycleId = jsonString(cycle, "cycle");
      const title = lifecycleTitle(product.id, cycleId);
      const labels = lifecycleLabels(product.category);

      entries.push({
        id: lifecycleEntryId(product.id, cycleId),
        title: `Compatibility review: ${title}`,
        labels,
        sourceId: `${source.id}:${product.id}`,
        body: reviewBody(
          product.category,
          product.url,
          `${title} appeared in ${source.id}.`,
          cycle,
        ),
      });
    }
  }

  return entries;
}

function lifecycleCycles(product: LifecycleProduct, cycles: unknown[]): any[] {
  let selected = cycles.filter(
    (cycle) => isRecord(cycle) && cycle.cycle !== undefined && !jsonValueHasPrereleaseMarker(cycle),
  );

  switch (product.id) {
    case "macos":
      selected = selected.filter((cycle) => {
        const major = Number.parseInt(String(cycle.cycle).split(".")[0] ?? "", 10);
        return Number.isFinite(major) && major >= 11;
      });
      break;
    case "rust":
      selected = selected.slice(0, 5);
      break;
    case "linux-kernel":
      selected = selected.slice(0, 8);
      break;
  }

  return selected;
}

function lifecycleEntryId(productId: string, cycle: string): string {
  switch (productId) {
    case "macos":
      return `macos:${cycle}`;
    case "rust":
      return `rust:${cycle}`;
    case "linux-kernel":
      return `linux-kernel:${cycle}`;
    default:
      return `${productId}:${cycle}`;
  }
}

function lifecycleTitle(productId: string, cycle: string): string {
  switch (productId) {
    case "macos":
      return `macOS ${cycle}`;
    case "rust":
      return `Rust ${cycle}`;
    case "linux-kernel":
      return `Linux kernel ${cycle}`;
    default:
      return `${productId} ${cycle}`;
  }
}

function lifecycleLabels(category: string): string[] {
  switch (category) {
    case "linux":
      return ["linux", "lifecycle"];
    case "macos":
      return ["macos", "lifecycle"];
    default:
      return ["toolchain", "lifecycle"];
  }
}

async function appleXcodeEntries(source: Source): Promise<ReviewEntry[]> {
  const url = sourceUrl(source);
  const text = await fetchText(url);
  const versions = uniqueXcodeVersions(text).slice(0, 5);

  return versions.map((version) => {
    const cycle = version.split(".")[0] ?? version;
    const details = { version };

    return {
      id: `xcode:${cycle}`,
      title: `Compatibility review: Xcode ${version}`,
      labels: ["toolchain", "lifecycle"],
      sourceId: source.id,
      body: reviewBody(
        source.category,
        url,
        `Xcode ${version} appeared in Apple developer releases.`,
        details,
      ),
    };
  });
}

function uniqueXcodeVersions(text: string): string[] {
  const versions: string[] = [];

  for (const line of text.split(/\r?\n/)) {
    if (textHasPrereleaseMarker(line)) {
      continue;
    }

    for (const part of line.split("Xcode ").slice(1)) {
      const version = takeVersion(part);
      if (version && !versions.includes(version)) {
        versions.push(version);
      }
    }
  }

  return versions;
}

async function llvmReleaseEntries(source: Source): Promise<ReviewEntry[]> {
  const url = sourceUrl(source);
  const payload = await fetchJson(url);
  if (!Array.isArray(payload)) {
    throw new Error("LLVM releases did not return a JSON array");
  }

  const entries: ReviewEntry[] = [];

  for (const release of payload) {
    if (!isRecord(release) || githubReleaseIsPrerelease(release)) {
      continue;
    }

    const tagName = typeof release.tag_name === "string" ? release.tag_name : undefined;
    if (!tagName) {
      continue;
    }

    const version = tagName.replace(/^llvmorg-/, "");
    const cycle = version.split(".")[0] ?? version;

    entries.push({
      id: `llvm:${cycle}`,
      title: `Compatibility review: LLVM ${version}`,
      labels: ["toolchain", "lifecycle"],
      sourceId: source.id,
      body: reviewBody(
        source.category,
        url,
        `LLVM ${version} appeared in upstream releases.`,
        release,
      ),
    });
  }

  return entries;
}

async function rustTargetEntries(source: Source): Promise<ReviewEntry[]> {
  const url = sourceUrl(source);
  const text = await fetchText(url);
  const triples = new Set<string>();

  for (const token of text.split(/[^A-Za-z0-9_-]+/)) {
    if ((token.match(/-/g) ?? []).length >= 2) {
      triples.add(token);
    }
  }

  return [...triples]
    .sort()
    .filter(trackedRustTarget)
    .map((triple) => {
      const category = triple.includes("linux") ? "linux" : "toolchain";
      const labels = category === "linux" ? ["linux", "toolchain"] : ["toolchain"];
      const details = { target: triple };

      return {
        id: `rust-target:${triple}`,
        title: `Compatibility review: Rust target ${triple}`,
        labels,
        sourceId: source.id,
        body: reviewBody(
          source.category,
          url,
          `Rust platform support lists target ${triple}.`,
          details,
        ),
      };
    });
}

function trackedRustTarget(triple: string): boolean {
  return (
    triple.includes("apple-darwin") ||
    [
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "i686-unknown-linux-gnu",
      "i686-unknown-linux-musl",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl",
    ].includes(triple)
  );
}

async function xnuCpuEntries(source: Source): Promise<ReviewEntry[]> {
  const url = sourceUrl(source);
  const text = await fetchText(url);
  const names = new Set<string>();

  for (const token of text.split(/[^A-Za-z0-9_]+/)) {
    const name = token.startsWith("CPU_TYPE_") ? token.slice("CPU_TYPE_".length) : undefined;
    if (name && trackedCpuName(name)) {
      names.add(name);
    }
  }

  return cpuNameEntries(source, url, names, "XNU CPU");
}

async function llvmArchEntries(source: Source): Promise<ReviewEntry[]> {
  const url = sourceUrl(source);
  const text = await fetchText(url);
  const enumBody = text.split("enum ArchType {")[1]?.split("};")[0] ?? "";
  const names = new Set<string>();

  for (const line of enumBody.split(/\r?\n/)) {
    const name = line.trimStart().match(/^[A-Za-z0-9_]+/)?.[0];
    if (name && trackedLlvmArch(name)) {
      names.add(name);
    }
  }

  return cpuNameEntries(source, url, names, "LLVM arch");
}

function cpuNameEntries(
  source: Source,
  url: string,
  names: Set<string>,
  titlePrefix: string,
): ReviewEntry[] {
  return [...names].sort().map((name) => {
    const normalized = name.toLowerCase();
    const details = { arch: name };

    return {
      id: `cpu:${normalized}`,
      title: `Compatibility review: ${titlePrefix} ${name}`,
      labels: ["cpu-arch", "scanner-review"],
      sourceId: source.id,
      body: reviewBody(
        source.category,
        url,
        `${titlePrefix} ${name} appeared in ${source.id}.`,
        details,
      ),
    };
  });
}

function trackedCpuName(name: string): boolean {
  return [
    "ARM",
    "ARM64",
    "ARM64_32",
    "X86",
    "X86_64",
    "I386",
    "POWERPC",
    "POWERPC64",
    "RISCV",
    "LOONGARCH",
  ].includes(name.toUpperCase());
}

function trackedLlvmArch(name: string): boolean {
  return [
    "aarch64",
    "aarch64_32",
    "arm",
    "x86",
    "riscv32",
    "riscv64",
    "loongarch64",
    "ppc",
    "ppc64",
  ].includes(name.toLowerCase());
}

function knownEntry(entry: ReviewEntry, knownIds: Set<string>, knownAliases: Set<string>): boolean {
  const entryId = entry.id.toLowerCase();
  const entryValue = entryId.split(":")[1] ?? entryId;

  return knownIds.has(entryId) || knownAliases.has(entryValue);
}

function knownIdsForManifest(manifest: Manifest): Set<string> {
  const ids = new Set<string>();

  for (const cycle of macosCycles(manifest.operating_systems.macos)) {
    ids.add(`macos:${cycle.toLowerCase()}`);
  }

  for (const cycle of manifest.toolchains.xcode.tracked_cycles ?? []) {
    ids.add(`xcode:${cycle.toLowerCase()}`);
  }

  for (const cycle of manifest.toolchains.llvm.tracked_cycles ?? []) {
    ids.add(`llvm:${cycle.toLowerCase()}`);
  }

  for (const release of trackedRustReleases(manifest.toolchains.rust)) {
    ids.add(`rust:${release.toLowerCase()}`);
    ids.add(`rust:${release.split(".").slice(0, 2).join(".").toLowerCase()}`);
  }

  for (const target of manifest.toolchains.rust.tracked_targets ?? []) {
    ids.add(`rust-target:${target.toLowerCase()}`);
  }

  for (const series of manifest.operating_systems.linux.kernel_series ?? []) {
    ids.add(`linux-kernel:${series.toLowerCase()}`);
  }

  return ids;
}

function knownAliasesForManifest(manifest: Manifest): Set<string> {
  const aliases = new Set<string>();

  for (const cpu of manifest.cpu_architectures) {
    aliases.add(cpu.id.toLowerCase());

    for (const alias of cpu.aliases ?? []) {
      aliases.add(
        alias
          .toLowerCase()
          .replace(/^cpu_type_/, "")
          .replace(/^cpu_subtype_/, ""),
      );
    }
  }

  return aliases;
}

function macosCycles(macos: MacosSupport): string[] {
  return [...(macos.supported ?? []), ...(macos.best_effort ?? []), ...(macos.tracked ?? [])].map(
    (entry) => entry.cycle,
  );
}

function trackedRustReleases(rust: RustToolchain): string[] {
  return [...(rust.tracked_releases ?? []), rust.minimum, rust.pinned];
}

function reportEntries(entries: ReviewEntry[]): void {
  if (entries.length === 0) {
    console.log("No new compatibility entries detected.");
    return;
  }

  console.log(`Detected ${entries.length} compatibility entries requiring review:`);

  for (const entry of entries) {
    console.log(`- ${entry.title} [${entry.labels.join(", ")}] from ${entry.sourceId}`);
  }
}

function createReviewIssues(manifest: Manifest, entries: ReviewEntry[], repo?: string): void {
  commandAvailable("gh");

  for (const entry of entries) {
    if (issueExists(entry.title, repo)) {
      console.log(`Issue already exists: ${entry.title}`);
      continue;
    }

    createIssue(manifest, entry, repo);
  }
}

function issueExists(title: string, repo?: string): boolean {
  const args = [
    "issue",
    "list",
    "--state",
    "open",
    "--search",
    `${title} in:title`,
    "--json",
    "number",
    "--jq",
    "length",
  ];

  if (repo) {
    args.push("--repo", repo);
  }

  const output = runCommand("gh", args, "gh issue list");

  return output.trim() !== "0";
}

function createIssue(manifest: Manifest, entry: ReviewEntry, repo?: string): void {
  const labels = [...(manifest.labels?.base ?? []), ...entry.labels].sort();
  const joinedLabels = [...new Set(labels)].join(",");
  const args = [
    "issue",
    "create",
    "--title",
    entry.title,
    "--body",
    entry.body,
    "--label",
    joinedLabels,
  ];

  if (repo) {
    args.push("--repo", repo);
  }

  process.stdout.write(runCommand("gh", args, `gh issue create for ${entry.title}`));
}

function reviewBody(
  category: string,
  sourceUrl: string,
  summary: string,
  details: unknown,
): string {
  const detailsJson = JSON.stringify(details, null, 2);
  const issueLink = (() => {
    switch (category) {
      case "cpu-arch":
        return `Scanner coverage review: ${ISSUE_1}`;
      case "macos":
        return "macOS lifecycle review for DYLD and hardened-runtime behavior.";
      case "linux":
        return `Linux support review: ${ISSUE_2}`;
      case "toolchain":
        return "Toolchain review for Rust, LLVM, and Xcode behavior.";
      case "runtime":
        return "Runtime integrity review for exact executable trust.";
      default:
        return "Compatibility manifest review required.";
    }
  })();

  return `${summary}\n\nSource: ${sourceUrl}\n\n${issueLink}\n\nThis tracker is intentionally review-only. If the entry is relevant, update \`compatibility-matrix.yaml\` in a separate human-reviewed change and decide whether scanner coverage (#1), Linux coverage (#2), or nightly validation needs follow-up.\n\n\`\`\`json\n${detailsJson}\n\`\`\`\n`;
}

async function fetchJson(url: string): Promise<unknown> {
  return JSON.parse(await fetchText(url));
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, {
    headers: {
      "User-Agent": "stt-guard-compatibility-tracker",
    },
  });

  if (!response.ok) {
    throw new Error(`fetch failed for ${url}: ${response.status} ${response.statusText}`);
  }

  return response.text();
}

function commandAvailable(command: string): void {
  runCommand(command, ["--version"], `check command ${command}`);
}

function runCommand(command: string, args: string[], description: string): string {
  const result = Bun.spawnSync([command, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });

  if (!result.success) {
    throw new Error(`${description} failed: ${result.stderr.toString()}`);
  }

  return result.stdout.toString();
}

function sourceUrl(source: Source): string {
  if (!source.url) {
    throw new Error(`source ${source.id} has no url`);
  }

  return source.url;
}

function githubReleaseIsPrerelease(release: Record<string, unknown>): boolean {
  return (
    release.prerelease === true ||
    (typeof release.tag_name === "string" && textHasPrereleaseMarker(release.tag_name)) ||
    (typeof release.name === "string" && textHasPrereleaseMarker(release.name))
  );
}

function jsonValueHasPrereleaseMarker(value: unknown): boolean {
  if (typeof value === "string") {
    return textHasPrereleaseMarker(value);
  }

  if (Array.isArray(value)) {
    return value.some(jsonValueHasPrereleaseMarker);
  }

  if (isRecord(value)) {
    return Object.entries(value).some(([key, nestedValue]) => {
      const normalizedKey = key.toLowerCase();
      const prereleaseField =
        normalizedKey.includes("prerelease") ||
        normalizedKey.includes("pre_release") ||
        normalizedKey === "pre";

      return (
        (prereleaseField && nestedValue === true) || jsonValueHasPrereleaseMarker(nestedValue)
      );
    });
  }

  return false;
}

function textHasPrereleaseMarker(text: string): boolean {
  return text
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((token) => token.toLowerCase())
    .some(
      (token) =>
        ["alpha", "beta", "preview", "prerelease", "pre", "nightly"].includes(token) ||
        token.startsWith("rc"),
    );
}

function jsonString(value: unknown, key: string): string {
  if (!isRecord(value) || typeof value[key] !== "string") {
    throw new Error(`JSON entry missing string key ${key}`);
  }

  return value[key];
}

function takeVersion(text: string): string {
  return text.match(/^[0-9.]+/)?.[0] ?? "";
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

if (import.meta.main) {
  main();
}

export {
  githubReleaseIsPrerelease,
  jsonString,
  lifecycleCycles,
  textHasPrereleaseMarker,
  uniqueXcodeVersions,
};
