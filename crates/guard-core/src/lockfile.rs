//! Lockfile registry extractor (M003-S07).
//!
//! Parses package-manager lockfiles near the project root to discover
//! custom registry hostnames.  These are merged into the per-run snapshot
//! as allow entries so legitimate fetches from private registries
//! are not blocked.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct LockfileRegistries {
    pub lockfile_path: PathBuf,
    pub registries: BTreeSet<String>,
}

#[must_use]
pub fn discover_lockfile(cwd: &Path) -> Option<PathBuf> {
    const LOCKFILES: &[&str] = &[
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "Cargo.lock",
        "Pipfile.lock",
        "poetry.lock",
        "Gemfile.lock",
        "go.sum",
        "composer.lock",
    ];

    let mut dir = cwd.to_path_buf();
    for _ in 0..8 {
        for name in LOCKFILES {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if dir.join(".git").exists() {
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

#[must_use]
pub fn extract_registries(lockfile: &Path) -> Option<LockfileRegistries> {
    let name = lockfile.file_name()?.to_str()?;
    let content = std::fs::read_to_string(lockfile).ok()?;

    let registries = match name {
        "package-lock.json" => extract_npm_registries(&content),
        "yarn.lock" => extract_yarn_registries(&content),
        "Cargo.lock" => extract_cargo_registries(&content),
        "Pipfile.lock" => extract_pip_registries(&content),
        "composer.lock" => extract_composer_registries(&content),
        _ => BTreeSet::new(),
    };

    if registries.is_empty() {
        return None;
    }

    Some(LockfileRegistries {
        lockfile_path: lockfile.to_path_buf(),
        registries,
    })
}

fn extract_host_from_url(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    if host.contains('.') {
        Some(host.to_lowercase())
    } else {
        None
    }
}

fn extract_npm_registries(content: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return hosts,
    };

    walk_resolved(&v, &mut hosts);
    hosts
}

fn walk_resolved(v: &serde_json::Value, hosts: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(url)) = map.get("resolved") {
                if let Some(h) = extract_host_from_url(url) {
                    hosts.insert(h);
                }
            }
            for val in map.values() {
                walk_resolved(val, hosts);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                walk_resolved(val, hosts);
            }
        }
        _ => {}
    }
}

fn extract_yarn_registries(content: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("resolved \"") {
            let url = rest.trim_end_matches('"');
            if let Some(h) = extract_host_from_url(url) {
                hosts.insert(h);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("resolved: ") {
            let url = rest.trim_matches('"');
            if let Some(h) = extract_host_from_url(url) {
                hosts.insert(h);
            }
        }
    }
    hosts
}

fn extract_cargo_registries(content: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("source = \"") {
            let url = rest.trim_end_matches('"');
            if let Some(stripped) = url.strip_prefix("registry+") {
                if let Some(h) = extract_host_from_url(stripped) {
                    hosts.insert(h);
                }
            }
            if let Some(stripped) = url.strip_prefix("sparse+") {
                if let Some(h) = extract_host_from_url(stripped) {
                    hosts.insert(h);
                }
            }
        }
    }
    hosts
}

fn extract_pip_registries(content: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return hosts,
    };
    if let Some(serde_json::Value::Array(sources)) = v.get("_meta").and_then(|m| m.get("sources")) {
        for src in sources {
            if let Some(url) = src.get("url").and_then(|u| u.as_str()) {
                if let Some(h) = extract_host_from_url(url) {
                    hosts.insert(h);
                }
            }
        }
    }
    hosts
}

fn extract_composer_registries(content: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return hosts,
    };

    walk_dist(&v, &mut hosts);
    hosts
}

fn walk_dist(v: &serde_json::Value, hosts: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(dist) = map.get("dist") {
                if let Some(url) = dist.get("url").and_then(|u| u.as_str()) {
                    if let Some(h) = extract_host_from_url(url) {
                        hosts.insert(h);
                    }
                }
            }
            for val in map.values() {
                walk_dist(val, hosts);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                walk_dist(val, hosts);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_from_https_url() {
        assert_eq!(
            extract_host_from_url("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
            Some("registry.npmjs.org".into())
        );
    }

    #[test]
    fn extract_host_strips_port() {
        assert_eq!(
            extract_host_from_url("https://my-registry.example.com:8080/foo"),
            Some("my-registry.example.com".into())
        );
    }

    #[test]
    fn extract_host_rejects_no_dot() {
        assert_eq!(extract_host_from_url("https://localhost/foo"), None);
    }

    #[test]
    fn npm_lockfile_extracts_registries() {
        let content = r#"{
            "name": "test",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/left-pad": {
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                },
                "node_modules/private-pkg": {
                    "resolved": "https://npm.pkg.github.com/@myorg/private-pkg/-/private-pkg-1.0.0.tgz"
                }
            }
        }"#;
        let hosts = extract_npm_registries(content);
        assert!(hosts.contains("registry.npmjs.org"));
        assert!(hosts.contains("npm.pkg.github.com"));
    }

    #[test]
    fn yarn_lock_extracts_resolved() {
        let content = r#"left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc123"
  integrity sha512-xxx

"@scope/pkg@^2.0.0":
  version "2.0.0"
  resolved "https://npm.pkg.github.com/@scope/pkg/-/pkg-2.0.0.tgz"
"#;
        let hosts = extract_yarn_registries(content);
        assert!(hosts.contains("registry.yarnpkg.com"));
        assert!(hosts.contains("npm.pkg.github.com"));
    }

    #[test]
    fn cargo_lock_extracts_registries() {
        let content = r#"[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "private"
version = "0.1.0"
source = "sparse+https://cargo.private.example.com/index/"
"#;
        let hosts = extract_cargo_registries(content);
        assert!(hosts.contains("github.com"));
        assert!(hosts.contains("cargo.private.example.com"));
    }

    #[test]
    fn pipfile_lock_extracts_sources() {
        let content = r#"{
            "_meta": {
                "sources": [
                    {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true},
                    {"name": "private", "url": "https://pypi.private.example.com/simple", "verify_ssl": true}
                ]
            },
            "default": {}
        }"#;
        let hosts = extract_pip_registries(content);
        assert!(hosts.contains("pypi.org"));
        assert!(hosts.contains("pypi.private.example.com"));
    }

    #[test]
    fn discover_lockfile_finds_package_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("package-lock.json");
        std::fs::write(&lock, "{}").unwrap();
        let found = discover_lockfile(dir.path());
        assert_eq!(found.as_deref(), Some(lock.as_path()));
    }

    #[test]
    fn discover_lockfile_stops_at_git() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        let found = discover_lockfile(&sub);
        assert_eq!(
            found.as_deref(),
            Some(dir.path().join("package-lock.json").as_path())
        );
    }
}
