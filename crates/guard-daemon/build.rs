use std::path::Path;

fn main() {
    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("guard-core")
        .join("data");

    println!("cargo:rerun-if-changed={}", data_dir.display());

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let mut files: Vec<_> = std::fs::read_dir(&data_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", data_dir.display()))
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
                && e.file_name()
                    .to_str()
                    .is_some_and(is_network_policy_data_file)
        })
        .collect();
    files.sort_by_key(|e| e.file_name());

    let mut combined = String::from("entries:\n");
    for entry in files {
        let path = entry.path();
        println!("cargo:rerun-if-changed={}", path.display());
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        for line in content.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if line.starts_with("- ") {
                combined.push_str("  ");
                combined.push_str(line);
                combined.push('\n');
            } else if line.starts_with("  ") {
                combined.push_str("  ");
                combined.push_str(line);
                combined.push('\n');
            } else {
                combined.push_str("    ");
                combined.push_str(line);
                combined.push('\n');
            }
        }
    }

    // Keep YAML for reference / debugging
    let yaml_path = Path::new(&out_dir).join("rules_combined.yaml");
    std::fs::write(&yaml_path, &combined)
        .unwrap_or_else(|e| panic!("write {}: {e}", yaml_path.display()));

    // Parse YAML → JSON so the runtime only needs serde_json
    let parsed: serde_yml::Value =
        serde_yml::from_str(&combined).unwrap_or_else(|e| panic!("parse combined yaml: {e}"));
    let json = serde_json::to_string(&parsed).unwrap_or_else(|e| panic!("serialize to json: {e}"));
    let json_path = Path::new(&out_dir).join("rules_combined.json");
    std::fs::write(&json_path, &json)
        .unwrap_or_else(|e| panic!("write {}: {e}", json_path.display()));
}

fn is_network_policy_data_file(name: &str) -> bool {
    name.starts_with("trusted-registry-")
        || name.starts_with("malicious-")
        || name.starts_with("suspicious-")
}
