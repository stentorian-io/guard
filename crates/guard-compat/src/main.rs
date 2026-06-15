use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use serde::Deserialize;
use serde_json::Value;

const ISSUE_1: &str = "https://github.com/stentorian-io/guard/issues/1";
const ISSUE_2: &str = "https://github.com/stentorian-io/guard/issues/2";

#[derive(Parser, Debug)]
#[command(about = "Review-only compatibility drift tracker")]
struct Args {
    #[arg(long, default_value = "compatibility-matrix.yaml")]
    manifest: PathBuf,

    #[arg(long)]
    offline: bool,

    #[arg(long)]
    create_issues: bool,

    #[arg(long)]
    repo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: u64,
    sources: Vec<Source>,
    labels: Option<Labels>,
    cpu_architectures: Vec<CpuArchitecture>,
    operating_systems: OperatingSystems,
    toolchains: Toolchains,
}

#[derive(Debug, Deserialize)]
struct Labels {
    #[serde(default)]
    base: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Source {
    id: String,
    category: String,
    url: Option<String>,
    #[serde(default)]
    products: Vec<LifecycleProduct>,
}

#[derive(Debug, Deserialize)]
struct LifecycleProduct {
    id: String,
    category: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct CpuArchitecture {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OperatingSystems {
    macos: MacosSupport,
    linux: LinuxSupport,
}

#[derive(Debug, Deserialize)]
struct MacosSupport {
    #[serde(default)]
    supported: Vec<CycleEntry>,
    #[serde(default)]
    best_effort: Vec<CycleEntry>,
    #[serde(default)]
    tracked: Vec<CycleEntry>,
}

#[derive(Debug, Deserialize)]
struct CycleEntry {
    cycle: String,
}

#[derive(Debug, Deserialize)]
struct LinuxSupport {
    #[serde(default)]
    kernel_series: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Toolchains {
    xcode: ToolchainCycles,
    rust: RustToolchain,
    llvm: ToolchainCycles,
}

#[derive(Debug, Deserialize)]
struct ToolchainCycles {
    #[serde(default)]
    tracked_cycles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RustToolchain {
    minimum: String,
    pinned: String,
    #[serde(default)]
    tracked_releases: Vec<String>,
    #[serde(default)]
    tracked_targets: Vec<String>,
}

#[derive(Debug)]
struct ReviewEntry {
    id: String,
    title: String,
    labels: Vec<String>,
    source_id: String,
    body: String,
}

fn main() {
    let args = Args::parse();

    if let Err(error) = run(args) {
        eprintln!("compatibility tracker failed: {error}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    let repo = args
        .repo
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok());
    let manifest_text = fs::read_to_string(&args.manifest)
        .map_err(|error| format!("read {}: {error}", args.manifest.display()))?;
    let manifest: Manifest = serde_norway::from_str(&manifest_text)
        .map_err(|error| format!("parse {}: {error}", args.manifest.display()))?;

    validate_manifest(&manifest)?;

    if args.offline {
        println!(
            "Validated {}; offline mode did not fetch sources.",
            args.manifest.display()
        );
        return Ok(());
    }

    let known_ids = known_ids(&manifest);
    let known_aliases = known_aliases(&manifest);
    let review_entries = observed_entries(&manifest)?
        .into_iter()
        .filter(|entry| !known_entry(entry, &known_ids, &known_aliases))
        .collect::<Vec<_>>();

    report_entries(&review_entries);

    if args.create_issues {
        create_review_issues(&manifest, &review_entries, repo.as_deref())?;
        return Ok(());
    }

    if review_entries.is_empty() {
        Ok(())
    } else {
        std::process::exit(2);
    }
}

fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported compatibility manifest schema {}",
            manifest.schema_version
        ));
    }

    let mut source_ids = BTreeSet::new();
    let mut duplicate_source_ids = Vec::new();

    for source in &manifest.sources {
        if source.id.trim().is_empty() {
            return Err("source id must not be empty".to_string());
        }

        if !source_ids.insert(source.id.as_str()) {
            duplicate_source_ids.push(source.id.as_str());
        }

        if source.url.is_none() && source.products.is_empty() {
            return Err(format!("source {} needs url or products", source.id));
        }

        if source.url.is_some() && !source.products.is_empty() {
            return Err(format!(
                "source {} must use either url or products, not both",
                source.id
            ));
        }
    }

    if !duplicate_source_ids.is_empty() {
        return Err(format!(
            "duplicate source ids: {}",
            duplicate_source_ids.join(", ")
        ));
    }

    Ok(())
}

fn observed_entries(manifest: &Manifest) -> Result<Vec<ReviewEntry>, String> {
    let mut entries = Vec::new();
    let mut source_successes = 0;

    for source in &manifest.sources {
        match fetch_source_entries(source) {
            Ok(source_entries) => {
                source_successes += 1;
                entries.extend(source_entries);
            }
            Err(error) => eprintln!("warning: {} failed: {error}", source.id),
        }
    }

    if source_successes == 0 {
        return Err("all compatibility sources failed".to_string());
    }

    Ok(entries)
}

fn fetch_source_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    match source.id.as_str() {
        "apple-xnu-machine" => xnu_cpu_entries(source),
        "llvm-triple-definitions" => llvm_arch_entries(source),
        "rust-platform-support" => rust_target_entries(source),
        "endoflife-lifecycle" => lifecycle_entries(source),
        "apple-developer-releases" => apple_xcode_entries(source),
        "github-llvm-releases" => llvm_release_entries(source),
        _ => {
            eprintln!("warning: no fetcher for {}", source.id);
            Ok(Vec::new())
        }
    }
}

fn lifecycle_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let mut entries = Vec::new();

    for product in &source.products {
        let payload = fetch_json(&product.url)?;
        let cycles = payload
            .as_array()
            .ok_or_else(|| format!("{} did not return a JSON array", product.id))?;

        for cycle in lifecycle_cycles(product, cycles) {
            let cycle_id = json_string(cycle, "cycle")?;
            let title = lifecycle_title(&product.id, &cycle_id);
            let labels = lifecycle_labels(&product.category);

            entries.push(ReviewEntry {
                id: lifecycle_entry_id(&product.id, &cycle_id),
                title: format!("Compatibility review: {title}"),
                labels,
                source_id: format!("{}:{}", source.id, product.id),
                body: review_body(
                    &product.category,
                    &product.url,
                    &format!("{title} appeared in {}.", source.id),
                    cycle,
                )?,
            });
        }
    }

    Ok(entries)
}

fn lifecycle_cycles<'a>(product: &LifecycleProduct, cycles: &'a [Value]) -> Vec<&'a Value> {
    let mut selected = cycles
        .iter()
        .filter(|cycle| cycle.get("cycle").is_some())
        .collect::<Vec<_>>();

    match product.id.as_str() {
        "macos" => selected.retain(|cycle| {
            json_string(cycle, "cycle")
                .ok()
                .and_then(|cycle| {
                    cycle
                        .split('.')
                        .next()
                        .and_then(|major| major.parse::<u64>().ok())
                })
                .is_some_and(|major| major >= 11)
        }),
        "rust" => selected.truncate(5),
        "linux-kernel" => selected.truncate(8),
        _ => {}
    }

    selected
}

fn lifecycle_entry_id(product_id: &str, cycle: &str) -> String {
    match product_id {
        "macos" => format!("macos:{cycle}"),
        "rust" => format!("rust:{cycle}"),
        "linux-kernel" => format!("linux-kernel:{cycle}"),
        product_id => format!("{product_id}:{cycle}"),
    }
}

fn lifecycle_title(product_id: &str, cycle: &str) -> String {
    match product_id {
        "macos" => format!("macOS {cycle}"),
        "rust" => format!("Rust {cycle}"),
        "linux-kernel" => format!("Linux kernel {cycle}"),
        product_id => format!("{product_id} {cycle}"),
    }
}

fn lifecycle_labels(category: &str) -> Vec<String> {
    match category {
        "linux" => vec!["linux".to_string(), "lifecycle".to_string()],
        "macos" => vec!["macos".to_string(), "lifecycle".to_string()],
        _ => vec!["toolchain".to_string(), "lifecycle".to_string()],
    }
}

fn apple_xcode_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let text = fetch_text(url)?;
    let versions = unique_xcode_versions(&text).into_iter().take(5);
    let mut entries = Vec::new();

    for version in versions {
        let cycle = version.split('.').next().unwrap_or(&version).to_string();
        let details = serde_json::json!({ "version": version });

        entries.push(ReviewEntry {
            id: format!("xcode:{cycle}"),
            title: format!("Compatibility review: Xcode {version}"),
            labels: vec!["toolchain".to_string(), "lifecycle".to_string()],
            source_id: source.id.clone(),
            body: review_body(
                &source.category,
                url,
                &format!("Xcode {version} appeared in Apple developer releases."),
                &details,
            )?,
        });
    }

    Ok(entries)
}

fn unique_xcode_versions(text: &str) -> Vec<String> {
    let mut versions = Vec::new();

    for part in text.split("Xcode ").skip(1) {
        let version = part
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '.')
            .collect::<String>();

        if !version.is_empty() && !versions.contains(&version) {
            versions.push(version);
        }
    }

    versions
}

fn llvm_release_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let payload = fetch_json(url)?;
    let releases = payload
        .as_array()
        .ok_or_else(|| "LLVM releases did not return a JSON array".to_string())?;
    let mut entries = Vec::new();

    for release in releases {
        let Some(tag_name) = release.get("tag_name").and_then(Value::as_str) else {
            continue;
        };

        let version = tag_name.trim_start_matches("llvmorg-");
        let cycle = version.split('.').next().unwrap_or(version);

        entries.push(ReviewEntry {
            id: format!("llvm:{cycle}"),
            title: format!("Compatibility review: LLVM {version}"),
            labels: vec!["toolchain".to_string(), "lifecycle".to_string()],
            source_id: source.id.clone(),
            body: review_body(
                &source.category,
                url,
                &format!("LLVM {version} appeared in upstream releases."),
                release,
            )?,
        });
    }

    Ok(entries)
}

fn rust_target_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let text = fetch_text(url)?;
    let mut triples = BTreeSet::new();

    for token in text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
    }) {
        if token.matches('-').count() >= 2 {
            triples.insert(token.to_string());
        }
    }

    let mut entries = Vec::new();

    for triple in triples {
        if !tracked_rust_target(&triple) {
            continue;
        }

        let category = if triple.contains("linux") {
            "linux"
        } else {
            "toolchain"
        };
        let labels = if category == "linux" {
            vec!["linux".to_string(), "toolchain".to_string()]
        } else {
            vec!["toolchain".to_string()]
        };
        let details = serde_json::json!({ "target": triple });

        entries.push(ReviewEntry {
            id: format!("rust-target:{triple}"),
            title: format!("Compatibility review: Rust target {triple}"),
            labels,
            source_id: source.id.clone(),
            body: review_body(
                &source.category,
                url,
                &format!("Rust platform support lists target {triple}."),
                &details,
            )?,
        });
    }

    Ok(entries)
}

fn tracked_rust_target(triple: &str) -> bool {
    triple.contains("apple-darwin")
        || matches!(
            triple,
            "aarch64-unknown-linux-gnu"
                | "aarch64-unknown-linux-musl"
                | "i686-unknown-linux-gnu"
                | "i686-unknown-linux-musl"
                | "x86_64-unknown-linux-gnu"
                | "x86_64-unknown-linux-musl"
        )
}

fn xnu_cpu_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let text = fetch_text(url)?;
    let mut names = BTreeSet::new();

    for token in
        text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
    {
        if let Some(name) = token.strip_prefix("CPU_TYPE_") {
            if tracked_cpu_name(name) {
                names.insert(name.to_string());
            }
        }
    }

    cpu_name_entries(source, url, names, "XNU CPU")
}

fn llvm_arch_entries(source: &Source) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let text = fetch_text(url)?;
    let enum_body = text
        .split("enum ArchType {")
        .nth(1)
        .and_then(|tail| tail.split("};").next())
        .unwrap_or_default();
    let mut names = BTreeSet::new();

    for line in enum_body.lines() {
        let trimmed = line.trim_start();
        let name = trimmed
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();

        if !name.is_empty() && tracked_llvm_arch(&name) {
            names.insert(name);
        }
    }

    cpu_name_entries(source, url, names, "LLVM arch")
}

fn cpu_name_entries(
    source: &Source,
    url: &str,
    names: BTreeSet<String>,
    title_prefix: &str,
) -> Result<Vec<ReviewEntry>, String> {
    let mut entries = Vec::new();

    for name in names {
        let normalized = name.to_ascii_lowercase();
        let details = serde_json::json!({ "arch": name });

        entries.push(ReviewEntry {
            id: format!("cpu:{normalized}"),
            title: format!("Compatibility review: {title_prefix} {name}"),
            labels: vec!["cpu-arch".to_string(), "scanner-review".to_string()],
            source_id: source.id.clone(),
            body: review_body(
                &source.category,
                url,
                &format!("{title_prefix} {name} appeared in {}.", source.id),
                &details,
            )?,
        });
    }

    Ok(entries)
}

fn tracked_cpu_name(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "ARM"
            | "ARM64"
            | "ARM64_32"
            | "X86"
            | "X86_64"
            | "I386"
            | "POWERPC"
            | "POWERPC64"
            | "RISCV"
            | "LOONGARCH"
    )
}

fn tracked_llvm_arch(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "aarch64"
            | "aarch64_32"
            | "arm"
            | "x86"
            | "riscv32"
            | "riscv64"
            | "loongarch64"
            | "ppc"
            | "ppc64"
    )
}

fn known_entry(
    entry: &ReviewEntry,
    known_ids: &BTreeSet<String>,
    known_aliases: &BTreeSet<String>,
) -> bool {
    let entry_id = entry.id.to_ascii_lowercase();
    let entry_value = entry_id
        .split_once(':')
        .map_or(entry_id.as_str(), |(_, value)| value);

    known_ids.contains(&entry_id) || known_aliases.contains(entry_value)
}

fn known_ids(manifest: &Manifest) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();

    for cycle in macos_cycles(&manifest.operating_systems.macos) {
        ids.insert(format!("macos:{}", cycle.to_ascii_lowercase()));
    }

    for cycle in &manifest.toolchains.xcode.tracked_cycles {
        ids.insert(format!("xcode:{}", cycle.to_ascii_lowercase()));
    }

    for cycle in &manifest.toolchains.llvm.tracked_cycles {
        ids.insert(format!("llvm:{}", cycle.to_ascii_lowercase()));
    }

    for release in tracked_rust_releases(&manifest.toolchains.rust) {
        ids.insert(format!("rust:{}", release.to_ascii_lowercase()));

        let major_minor = release.split('.').take(2).collect::<Vec<_>>().join(".");
        ids.insert(format!("rust:{}", major_minor.to_ascii_lowercase()));
    }

    for target in &manifest.toolchains.rust.tracked_targets {
        ids.insert(format!("rust-target:{}", target.to_ascii_lowercase()));
    }

    for series in &manifest.operating_systems.linux.kernel_series {
        ids.insert(format!("linux-kernel:{}", series.to_ascii_lowercase()));
    }

    ids
}

fn known_aliases(manifest: &Manifest) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();

    for cpu in &manifest.cpu_architectures {
        aliases.insert(cpu.id.to_ascii_lowercase());

        for alias in &cpu.aliases {
            aliases.insert(
                alias
                    .to_ascii_lowercase()
                    .trim_start_matches("cpu_type_")
                    .trim_start_matches("cpu_subtype_")
                    .to_string(),
            );
        }
    }

    aliases
}

fn macos_cycles(macos: &MacosSupport) -> Vec<&str> {
    macos
        .supported
        .iter()
        .chain(&macos.best_effort)
        .chain(&macos.tracked)
        .map(|entry| entry.cycle.as_str())
        .collect()
}

fn tracked_rust_releases(rust: &RustToolchain) -> Vec<&str> {
    rust.tracked_releases
        .iter()
        .map(String::as_str)
        .chain([rust.minimum.as_str(), rust.pinned.as_str()])
        .collect()
}

fn report_entries(entries: &[ReviewEntry]) {
    if entries.is_empty() {
        println!("No new compatibility entries detected.");
        return;
    }

    println!(
        "Detected {} compatibility entries requiring review:",
        entries.len()
    );

    for entry in entries {
        println!(
            "- {} [{}] from {}",
            entry.title,
            entry.labels.join(", "),
            entry.source_id
        );
    }
}

fn create_review_issues(
    manifest: &Manifest,
    entries: &[ReviewEntry],
    repo: Option<&str>,
) -> Result<(), String> {
    command_available("gh")?;

    for entry in entries {
        if issue_exists(&entry.title, repo)? {
            println!("Issue already exists: {}", entry.title);
            continue;
        }

        create_issue(manifest, entry, repo)?;
    }

    Ok(())
}

fn issue_exists(title: &str, repo: Option<&str>) -> Result<bool, String> {
    let search = format!("{title} in:title");
    let mut command = Command::new("gh");
    command.args([
        "issue", "list", "--state", "open", "--search", &search, "--json", "number", "--jq",
        "length",
    ]);

    if let Some(repo) = repo {
        command.args(["--repo", repo]);
    }

    let output = command
        .output()
        .map_err(|error| format!("run gh issue list: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh issue list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim() != "0")
}

fn create_issue(
    manifest: &Manifest,
    entry: &ReviewEntry,
    repo: Option<&str>,
) -> Result<(), String> {
    let mut labels = manifest
        .labels
        .as_ref()
        .map(|labels| labels.base.clone())
        .unwrap_or_default();
    labels.extend(entry.labels.clone());
    labels.sort();
    labels.dedup();

    let joined_labels = labels.join(",");
    let mut command = Command::new("gh");
    command.args([
        "issue",
        "create",
        "--title",
        &entry.title,
        "--body",
        &entry.body,
        "--label",
        &joined_labels,
    ]);

    if let Some(repo) = repo {
        command.args(["--repo", repo]);
    }

    let output = command
        .output()
        .map_err(|error| format!("run gh issue create: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh issue create failed for {}: {}",
            entry.title,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

fn review_body(
    category: &str,
    source_url: &str,
    summary: &str,
    details: &Value,
) -> Result<String, String> {
    let details = serde_json::to_string_pretty(details)
        .map_err(|error| format!("serialize review details: {error}"))?;
    let issue_link = match category {
        "cpu-arch" => format!("Scanner coverage review: {ISSUE_1}"),
        "macos" => "macOS lifecycle review for DYLD and hardened-runtime behavior.".to_string(),
        "linux" => format!("Linux support review: {ISSUE_2}"),
        "toolchain" => "Toolchain review for Rust, LLVM, and Xcode behavior.".to_string(),
        "runtime" => "Runtime integrity review for exact executable trust.".to_string(),
        _ => "Compatibility manifest review required.".to_string(),
    };

    Ok(format!(
        "{summary}\n\nSource: {source_url}\n\n{issue_link}\n\nThis tracker is intentionally review-only. If the entry is relevant, update `compatibility-matrix.yaml` in a separate human-reviewed change and decide whether scanner coverage (#1), Linux coverage (#2), or nightly validation needs follow-up.\n\n```json\n{details}\n```\n"
    ))
}

fn fetch_json(url: &str) -> Result<Value, String> {
    let text = fetch_text(url)?;

    serde_json::from_str(&text).map_err(|error| format!("parse JSON from {url}: {error}"))
}

fn fetch_text(url: &str) -> Result<String, String> {
    let output = Command::new("curl")
        .args(["-fsSL", "-A", "stt-guard-compatibility-tracker", url])
        .output()
        .map_err(|error| format!("run curl for {url}: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "curl failed for {url}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    String::from_utf8(output.stdout).map_err(|error| format!("decode UTF-8 from {url}: {error}"))
}

fn command_available(command: &str) -> Result<(), String> {
    let status = Command::new(command)
        .arg("--version")
        .status()
        .map_err(|error| format!("check command {command}: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{command} is unavailable; cannot create review issues"
        ))
    }
}

fn source_url(source: &Source) -> Result<&str, String> {
    source
        .url
        .as_deref()
        .ok_or_else(|| format!("source {} has no url", source.id))
}

fn json_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("JSON entry missing string key {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
schema_version: 1
sources:
  - id: github-llvm-releases
    category: toolchain
    url: https://api.github.com/repos/llvm/llvm-project/releases?per_page=10
labels:
  base:
    - compatibility
cpu_architectures:
  - id: arm64
    aliases:
      - aarch64
operating_systems:
  macos:
    supported:
      - cycle: "26"
    best_effort: []
    tracked: []
  linux:
    kernel_series:
      - "6.12"
toolchains:
  xcode:
    tracked_cycles:
      - "26"
  rust:
    minimum: "1.85.0"
    pinned: "1.95.0"
    tracked_releases:
      - "1.95.0"
    tracked_targets:
      - aarch64-apple-darwin
  llvm:
    tracked_cycles:
      - "21"
"#;

    fn manifest() -> Manifest {
        serde_norway::from_str(MANIFEST).expect("test manifest")
    }

    #[test]
    fn known_ids_include_reviewed_toolchain_releases() {
        let manifest = manifest();
        let known_ids = known_ids(&manifest);

        assert!(known_ids.contains("llvm:21"));
        assert!(known_ids.contains("rust:1.95.0"));
        assert!(known_ids.contains("rust-target:aarch64-apple-darwin"));
    }
}
