use std::path::Path;

fn main() {
    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("sentinel-core")
        .join("data");

    let allow_dir = data_dir.join("allow");
    let deny_dir = data_dir.join("deny");

    println!("cargo:rerun-if-changed={}", allow_dir.display());
    println!("cargo:rerun-if-changed={}", deny_dir.display());

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("rules_combined.yaml");

    let mut combined = String::from("entries:\n");

    for (dir, kind) in [(&allow_dir, "allow"), (&deny_dir, "deny")] {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

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
                    combined.push_str(&format!("  - kind: {kind}\n"));
                    let rest = line.trim_start_matches("- ");
                    combined.push_str(&format!("    {rest}\n"));
                } else if line.starts_with("  ") {
                    combined.push_str(&format!("  {line}\n"));
                } else {
                    combined.push_str(&format!("    {line}\n"));
                }
            }
        }
    }

    std::fs::write(&out_path, &combined)
        .unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
}
