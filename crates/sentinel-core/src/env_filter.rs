//! Centralized PM env filtering constants.
//!
//! Single source of truth for the prefix allowlist, secret denylist, and
//! credential substring patterns used by the hook (dylib-side capture),
//! daemon (server-side re-filter), and CLI (root env capture).

/// PM env-key allowlist (prefix match). A captured env var is admitted only
/// if its key starts with one of these prefixes.
pub const PM_ENV_PREFIXES: &[&str] = &[
    "npm_",
    "PIP_",
    "VIRTUAL_ENV",
    "CARGO_",
    "BUNDLE_",
    "GEM_HOME",
    "GOPATH",
    "GOBIN",
    "GOPROXY",
    "GOMODCACHE",
    "GOROOT",
    "GOFLAGS",
    "GONOSUMCHECK",
    "GONOSUMDB",
    "GONOPROXY",
    "GOPRIVATE",
    "MIX_",
    "HEX_",
    "COMPOSER_",
];

/// Case-insensitive exact-match denylist. Takes precedence over the prefix
/// allowlist — a key that matches both is dropped.
pub const SECRET_DENYLIST: &[&str] = &[
    "npm_config_authToken",
    "npm_config_password",
    "npm_config_email",
    "npm_config__auth",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "BUNDLE_GITHUB__COM",
    "BUNDLE_GEMS__CONTRIBSYS__COM",
    "CARGO_REGISTRY_TOKEN",
    "COMPOSER_AUTH",
];

/// Substring patterns that suggest a key holds credentials. Match is
/// case-insensitive on the upper-cased key.
pub const SECRET_SUBSTRING_PATTERNS: &[&str] = &[
    "TOKEN",
    "PASSWORD",
    "SECRET",
    "PASSWD",
    "APIKEY",
    "API_KEY",
];

/// Returns true if `key` is on the denylist or contains a credential-like
/// substring pattern.
pub fn is_secret_key(key: &str) -> bool {
    if SECRET_DENYLIST.iter().any(|d| d.eq_ignore_ascii_case(key)) {
        return true;
    }
    let upper = key.to_ascii_uppercase();
    if SECRET_SUBSTRING_PATTERNS.iter().any(|p| upper.contains(p)) {
        return true;
    }
    if upper.ends_with("_AUTH") || upper.contains("__AUTH") {
        return true;
    }
    false
}

/// Returns true if `key` starts with any prefix in the allowlist.
pub fn is_pm_env_key(key: &str) -> bool {
    PM_ENV_PREFIXES.iter().any(|p| key.starts_with(p))
}

pub const MAX_VALUE_BYTES: usize = 512;

/// Truncate a value to `MAX_VALUE_BYTES` respecting UTF-8 char boundaries.
pub fn truncate_value(value: &str) -> &str {
    if value.len() <= MAX_VALUE_BYTES {
        return value;
    }
    let mut end = MAX_VALUE_BYTES;
    while !value.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_prefixes_are_explicit() {
        assert!(is_pm_env_key("GOPATH"));
        assert!(is_pm_env_key("GOBIN"));
        assert!(is_pm_env_key("GOPROXY"));
        assert!(is_pm_env_key("GOMODCACHE"));
        assert!(is_pm_env_key("GOROOT"));
        assert!(is_pm_env_key("GOFLAGS"));
        assert!(is_pm_env_key("GOPRIVATE"));
        assert!(!is_pm_env_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(!is_pm_env_key("GOTRACEBACK"));
        assert!(!is_pm_env_key("GONK"));
    }

    #[test]
    fn secret_denylist_takes_precedence() {
        assert!(is_secret_key("npm_config_authToken"));
        assert!(is_secret_key("CARGO_REGISTRY_TOKEN"));
        assert!(is_secret_key("COMPOSER_AUTH"));
    }

    #[test]
    fn secret_substring_patterns_match() {
        assert!(is_secret_key("npm_some_TOKEN_field"));
        assert!(is_secret_key("SOME_PASSWORD_VAR"));
        assert!(is_secret_key("MY_API_KEY"));
    }

    #[test]
    fn auth_suffix_detected() {
        assert!(is_secret_key("BUNDLE_GITHUB__AUTH"));
        assert!(is_secret_key("npm_config__auth"));
    }

    #[test]
    fn non_secret_passes() {
        assert!(!is_secret_key("npm_package_name"));
        assert!(!is_secret_key("CARGO_PKG_NAME"));
        assert!(!is_secret_key("PIP_NO_CACHE_DIR"));
    }

    #[test]
    fn truncate_respects_utf8() {
        let short = "hello";
        assert_eq!(truncate_value(short), "hello");

        let long = "X".repeat(1024);
        assert_eq!(truncate_value(&long).len(), MAX_VALUE_BYTES);
    }
}
