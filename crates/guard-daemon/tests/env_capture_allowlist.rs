//! v0.3 — PM env-allowlist + secret-denylist tests.
use guard_daemon::env_capture::extract_pm_env;

fn pair(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

#[test]
fn keeps_pm_keys() {
    let env = vec![
        pair("npm_package_name", "lodash"),
        pair("npm_lifecycle_event", "postinstall"),
        pair("PIP_INDEX_VERSION", "1"),
        pair("VIRTUAL_ENV", "/proj/.venv"),
        pair("CARGO_PKG_NAME", "stt-guard"),
        pair("CARGO_PKG_VERSION", "0.3.0"),
        pair("BUNDLE_PATH", "vendor/bundle"),
        pair("GEM_HOME", "/Users/me/.gem"),
        pair("GOPATH", "/Users/me/go"),
        pair("GOPROXY", "https://proxy.golang.org"),
        pair("MIX_ENV", "test"),
        pair("HEX_HOME", "/Users/me/.hex"),
        pair("COMPOSER_HOME", "/Users/me/.composer"),
    ];
    let out = extract_pm_env(&env);
    assert_eq!(out.len(), env.len(), "all PM-prefixed keys must survive");
    // Order preserved (Vec semantics):
    assert_eq!(out[0].0, "npm_package_name");
    assert_eq!(out[12].0, "COMPOSER_HOME");
}

#[test]
fn denylist_blocks_secret_keys() {
    let env = vec![
        pair("npm_config_authToken", "supersecret_TOKEN"),
        pair("npm_config_password", "p4ssw0rd"),
        pair("npm_config_email", "alice@example.com"),
        pair("npm_config__auth", "Basic xyz"),
        pair(
            "PIP_INDEX_URL",
            "https://user:pass@pypi.example.com/simple/",
        ),
        pair("PIP_EXTRA_INDEX_URL", "https://creds@private.example.com/"),
        pair("BUNDLE_GITHUB__COM", "ghp_abc"),
        pair("BUNDLE_GEMS__CONTRIBSYS__COM", "ghp_def"),
        pair("CARGO_REGISTRY_TOKEN", "cio0123456789"),
        pair("COMPOSER_AUTH", "{\"github-oauth\":\"token\"}"),
        // benign control:
        pair("npm_package_name", "lodash"),
    ];
    let out = extract_pm_env(&env);
    let captured_keys: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
    // Only the benign control survived:
    assert_eq!(captured_keys, vec!["npm_package_name"]);
    // Negative-grep: no captured value contains the secret payloads.
    let captured_vals: String = out
        .iter()
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join("|");
    assert!(!captured_vals.contains("supersecret_TOKEN"));
    assert!(!captured_vals.contains("ghp_abc"));
    assert!(!captured_vals.contains("cio0123456789"));
}

#[test]
fn rejects_non_pm_keys() {
    let env = vec![
        pair("HOME", "/Users/me"),
        pair("PATH", "/usr/bin"),
        pair("USER", "me"),
        pair("AWS_ACCESS_KEY", "AKIA..."),
        pair("GITHUB_TOKEN", "ghp_..."),
        pair("RANDOM_VAR", "random"),
        pair("npm_package_name", "lodash"), // control: this one passes
    ];
    let out = extract_pm_env(&env);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "npm_package_name");
}

#[test]
fn enforces_total_wire_cap() {
    let env: Vec<(String, String)> = (0..200)
        .map(|i| (format!("npm_filler_{i}"), "x".repeat(100)))
        .collect();
    let out = extract_pm_env(&env);
    let total: usize = out.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    assert!(
        total <= guard_ipc::ExecEvent::MAX_PM_ENV_BYTES,
        "total {total} > cap"
    );
    assert!(
        out.len() < 200,
        "cap should kick in well before 200 entries"
    );
}

#[test]
fn truncates_oversized_value() {
    let env = vec![pair("npm_package_name", &"x".repeat(5000))];
    let out = extract_pm_env(&env);
    assert_eq!(out.len(), 1);
    assert!(
        out[0].1.len() <= 512,
        "value not truncated to 512 bytes; got {}",
        out[0].1.len()
    );
}

#[test]
fn empty_input_returns_empty() {
    assert!(extract_pm_env(&[]).is_empty());
}
