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

    #[arg(long, default_value = "crates/guard-core/data/trusted-runtimes.yaml")]
    trusted_runtimes: PathBuf,

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
    runtime_integrity: Option<RuntimeIntegrity>,
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
struct RuntimeIntegrity {
    #[serde(default)]
    runtimes: Vec<RuntimeReview>,
}

#[derive(Debug, Deserialize)]
struct RuntimeReview {
    id: String,
    name: String,
    #[serde(default)]
    reviewed_releases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TrustedRuntimeRegistry {
    #[serde(default)]
    runtimes: Vec<TrustedRuntime>,
}

#[derive(Debug, Deserialize)]
struct TrustedRuntime {
    sha256: String,
    name: String,
    version: String,
    source: String,
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
    let manifest: Manifest = serde_yml::from_str(&manifest_text)
        .map_err(|error| format!("parse {}: {error}", args.manifest.display()))?;
    let trusted_runtime_text = fs::read_to_string(&args.trusted_runtimes)
        .map_err(|error| format!("read {}: {error}", args.trusted_runtimes.display()))?;
    let trusted_runtimes: TrustedRuntimeRegistry = serde_yml::from_str(&trusted_runtime_text)
        .map_err(|error| format!("parse {}: {error}", args.trusted_runtimes.display()))?;

    validate_manifest(&manifest)?;
    validate_trusted_runtimes(&manifest, &trusted_runtimes)?;

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

    validate_runtime_reviews(manifest)?;

    Ok(())
}

fn validate_runtime_reviews(manifest: &Manifest) -> Result<(), String> {
    let Some(runtime_integrity) = &manifest.runtime_integrity else {
        return Ok(());
    };
    let mut runtime_ids = BTreeSet::new();

    for runtime in &runtime_integrity.runtimes {
        if runtime.id.trim().is_empty() {
            return Err("runtime id must not be empty".to_string());
        }

        if runtime.name.trim().is_empty() {
            return Err(format!("runtime {} name must not be empty", runtime.id));
        }

        if !runtime_ids.insert(runtime.id.as_str()) {
            return Err(format!("duplicate runtime id: {}", runtime.id));
        }

        if runtime.reviewed_releases.is_empty() {
            return Err(format!(
                "runtime {} needs at least one reviewed release",
                runtime.id
            ));
        }
    }

    Ok(())
}

fn validate_trusted_runtimes(
    manifest: &Manifest,
    registry: &TrustedRuntimeRegistry,
) -> Result<(), String> {
    let reviewed_runtime_releases = reviewed_runtime_releases(manifest);
    let mut trusted_hashes = BTreeSet::new();

    for runtime in &registry.runtimes {
        if parse_sha256_hex(&runtime.sha256).is_none() {
            return Err(format!(
                "trusted runtime {} {} has malformed sha256",
                runtime.name, runtime.version
            ));
        }

        let trusted_key = format!(
            "{}:{}",
            runtime.name.to_ascii_lowercase(),
            runtime.version.to_ascii_lowercase()
        );

        if !reviewed_runtime_releases.contains(&trusted_key) {
            return Err(format!(
                "trusted runtime {} {} is not reviewed in compatibility-matrix.yaml",
                runtime.name, runtime.version
            ));
        }

        if runtime.source.trim().is_empty() {
            return Err(format!(
                "trusted runtime {} {} source must not be empty",
                runtime.name, runtime.version
            ));
        }

        if !trusted_hashes.insert(runtime.sha256.to_ascii_lowercase()) {
            return Err(format!(
                "duplicate trusted runtime sha256 for {} {}",
                runtime.name, runtime.version
            ));
        }
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
        "github-node-releases" => github_runtime_release_entries(source, "node", 1),
        "github-python-releases" => github_runtime_release_entries(source, "python", 2),
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

fn github_runtime_release_entries(
    source: &Source,
    runtime_name: &str,
    version_precision: usize,
) -> Result<Vec<ReviewEntry>, String> {
    let url = source_url(source)?;
    let payload = fetch_json(url)?;
    let releases = payload
        .as_array()
        .ok_or_else(|| format!("{} did not return a JSON array", source.id))?;
    let mut cycles = BTreeSet::new();

    for release in releases {
        let Some(tag_name) = release.get("tag_name").and_then(Value::as_str) else {
            continue;
        };

        if let Some(cycle) = runtime_release_cycle(tag_name, version_precision) {
            cycles.insert(cycle);
        }
    }

    let mut entries = Vec::new();

    for cycle in cycles {
        let details = serde_json::json!({
            "runtime": runtime_name,
            "release": cycle,
        });

        entries.push(ReviewEntry {
            id: format!("runtime:{runtime_name}:{cycle}"),
            title: format!("Compatibility review: {runtime_name} runtime {cycle}"),
            labels: vec![
                "runtime".to_string(),
                "integrity".to_string(),
                "scanner-review".to_string(),
            ],
            source_id: source.id.clone(),
            body: review_body(
                &source.category,
                url,
                &format!("{runtime_name} runtime release {cycle} appeared upstream."),
                &details,
            )?,
        });
    }

    Ok(entries)
}

fn runtime_release_cycle(tag_name: &str, version_precision: usize) -> Option<String> {
    let version = tag_name
        .trim_start_matches('v')
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .next()
        .unwrap_or_default();

    let parts = version
        .split('.')
        .filter(|part| !part.is_empty())
        .take(version_precision)
        .collect::<Vec<_>>();

    if parts.len() == version_precision {
        Some(parts.join("."))
    } else {
        None
    }
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

    for runtime_release in reviewed_runtime_release_ids(manifest) {
        ids.insert(runtime_release);
    }

    ids
}

fn reviewed_runtime_release_ids(manifest: &Manifest) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();

    for (runtime_name, release) in reviewed_runtime_release_pairs(manifest) {
        ids.insert(format!("runtime:{runtime_name}:{release}"));
    }

    ids
}

fn reviewed_runtime_releases(manifest: &Manifest) -> BTreeSet<String> {
    let mut releases = BTreeSet::new();

    for (runtime_name, release) in reviewed_runtime_release_pairs(manifest) {
        releases.insert(format!("{runtime_name}:{release}"));
    }

    releases
}

fn reviewed_runtime_release_pairs(manifest: &Manifest) -> Vec<(String, String)> {
    let Some(runtime_integrity) = &manifest.runtime_integrity else {
        return Vec::new();
    };
    let mut releases = Vec::new();

    for runtime in &runtime_integrity.runtimes {
        let runtime_name = runtime.name.to_ascii_lowercase();

        for release in &runtime.reviewed_releases {
            releases.push((runtime_name.clone(), release.to_ascii_lowercase()));
        }
    }

    releases
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

fn parse_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }

    let mut out = [0u8; 32];

    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }

    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
schema_version: 1
sources:
  - id: github-node-releases
    category: runtime
    url: https://api.github.com/repos/nodejs/node/releases?per_page=10
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
runtime_integrity:
  runtimes:
    - id: node
      name: node
      reviewed_releases:
        - "24"
        - "22.21"
"#;

    fn manifest() -> Manifest {
        serde_yml::from_str(MANIFEST).expect("test manifest")
    }

    #[test]
    fn runtime_release_cycle_uses_requested_precision() {
        assert_eq!(runtime_release_cycle("v24.11.1", 1).as_deref(), Some("24"));
        assert_eq!(
            runtime_release_cycle("v3.14.0rc1", 2).as_deref(),
            Some("3.14")
        );
        assert_eq!(runtime_release_cycle("not-a-version", 1), None);
    }

    #[test]
    fn known_ids_include_reviewed_runtime_releases() {
        let manifest = manifest();
        let known_ids = known_ids(&manifest);

        assert!(known_ids.contains("runtime:node:24"));
        assert!(known_ids.contains("runtime:node:22.21"));
    }

    #[test]
    fn trusted_runtime_hashes_must_reference_reviewed_releases() {
        let manifest = manifest();
        let registry = TrustedRuntimeRegistry {
            runtimes: vec![TrustedRuntime {
                sha256: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    .to_string(),
                name: "node".to_string(),
                version: "24".to_string(),
                source: "https://nodejs.org/dist/v24.0.0/".to_string(),
            }],
        };

        validate_trusted_runtimes(&manifest, &registry).expect("reviewed runtime");
    }

    #[test]
    fn unreviewed_trusted_runtime_hashes_are_rejected() {
        let manifest = manifest();
        let registry = TrustedRuntimeRegistry {
            runtimes: vec![TrustedRuntime {
                sha256: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    .to_string(),
                name: "node".to_string(),
                version: "25".to_string(),
                source: "https://nodejs.org/dist/v25.0.0/".to_string(),
            }],
        };

        let error = validate_trusted_runtimes(&manifest, &registry)
            .expect_err("unreviewed runtime should fail validation");

        assert!(error.contains("is not reviewed"));
    }
}
