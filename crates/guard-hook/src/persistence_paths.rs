//! Persistence-path classifier for open/openat monitoring (M003-S04, S06).
//!
//! S06 extends the classifier with an OS-version-aware persistence-path
//! matrix covering macOS 13 (Ventura) through 15+ (Sequoia).

pub use guard_os::system::macos_major_version;

/// Check if `path` targets a macOS persistence location.
/// Returns the persistence category if matched, None otherwise.
///
/// `path` and `home` are raw byte slices (no NUL terminator).
/// Zero-allocation: all comparisons are bytewise on the stack.
pub fn classify_persistence_path(path: &[u8], home: &[u8]) -> Option<&'static str> {
    classify_persistence_path_with_version(path, home, macos_major_version())
}

/// Version-parameterized classifier for testing.
pub fn classify_persistence_path_with_version(
    path: &[u8],
    home: &[u8],
    macos_major: u32,
) -> Option<&'static str> {
    // ---- LaunchAgents (all macOS versions) ----
    if starts_with_home_then(path, home, b"/Library/LaunchAgents/") {
        return Some("launch-agent");
    }
    if path.starts_with(b"/Library/LaunchAgents/") {
        return Some("launch-agent");
    }

    // ---- LaunchDaemons (all macOS versions) ----
    if path.starts_with(b"/Library/LaunchDaemons/") {
        return Some("launch-daemon");
    }

    // ---- Login items: macOS 13+ (Ventura) uses backgroundtaskmanagementagent ----
    if macos_major >= 13
        && starts_with_home_then(
            path,
            home,
            b"/Library/Application Support/com.apple.backgroundtaskmanagementagent/",
        )
    {
        return Some("login-item");
    }

    // ---- Login items: pre-Ventura uses LSSharedFileList plist ----
    if macos_major < 13
        && starts_with_home_then(
            path,
            home,
            b"/Library/Preferences/com.apple.loginitems.plist",
        )
    {
        return Some("login-item");
    }

    // ---- Crontab (all macOS versions) ----
    if path.starts_with(b"/usr/lib/cron/tabs/") || path.starts_with(b"/var/at/tabs/") {
        return Some("crontab");
    }

    // ---- Periodic scripts (all macOS versions) ----
    if path.starts_with(b"/etc/periodic/daily/")
        || path.starts_with(b"/etc/periodic/weekly/")
        || path.starts_with(b"/etc/periodic/monthly/")
        || path.starts_with(b"/usr/local/etc/periodic/")
    {
        return Some("periodic-script");
    }

    // ---- Shell profile injection (all versions) ----
    if starts_with_home_then(path, home, b"/.bash_profile")
        || starts_with_home_then(path, home, b"/.bashrc")
        || starts_with_home_then(path, home, b"/.zshrc")
        || starts_with_home_then(path, home, b"/.zshenv")
        || starts_with_home_then(path, home, b"/.profile")
        || starts_with_home_then(path, home, b"/.zprofile")
    {
        return Some("shell-profile");
    }

    None
}

fn starts_with_home_then(path: &[u8], home: &[u8], suffix: &[u8]) -> bool {
    if home.is_empty() {
        return false;
    }
    if !path.starts_with(home) {
        return false;
    }
    path[home.len()..].starts_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &[u8] = b"/Users/test";

    fn classify(path: &[u8], ver: u32) -> Option<&'static str> {
        classify_persistence_path_with_version(path, HOME, ver)
    }

    #[test]
    fn launch_agent_user() {
        assert_eq!(
            classify(b"/Users/test/Library/LaunchAgents/evil.plist", 14),
            Some("launch-agent")
        );
    }

    #[test]
    fn launch_agent_system() {
        assert_eq!(
            classify(b"/Library/LaunchAgents/evil.plist", 14),
            Some("launch-agent")
        );
    }

    #[test]
    fn launch_daemon() {
        assert_eq!(
            classify(b"/Library/LaunchDaemons/evil.plist", 14),
            Some("launch-daemon")
        );
    }

    #[test]
    fn login_item_ventura_plus() {
        let path = b"/Users/test/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm";
        assert_eq!(classify(path, 13), Some("login-item"));
        assert_eq!(classify(path, 14), Some("login-item"));
        assert_eq!(classify(path, 15), Some("login-item"));
        // Pre-Ventura: backgroundtaskmanagementagent not used
        assert_eq!(classify(path, 12), None);
    }

    #[test]
    fn login_item_pre_ventura() {
        let path = b"/Users/test/Library/Preferences/com.apple.loginitems.plist";
        assert_eq!(classify(path, 12), Some("login-item"));
        // Ventura+: old plist path not monitored
        assert_eq!(classify(path, 13), None);
    }

    #[test]
    fn crontab() {
        assert_eq!(classify(b"/usr/lib/cron/tabs/root", 14), Some("crontab"));
        assert_eq!(classify(b"/var/at/tabs/user", 14), Some("crontab"));
    }

    #[test]
    fn periodic_scripts() {
        assert_eq!(
            classify(b"/etc/periodic/daily/evil.sh", 14),
            Some("periodic-script")
        );
        assert_eq!(
            classify(b"/etc/periodic/weekly/mine.sh", 14),
            Some("periodic-script")
        );
        assert_eq!(
            classify(b"/etc/periodic/monthly/cron.sh", 14),
            Some("periodic-script")
        );
        assert_eq!(
            classify(b"/usr/local/etc/periodic/evil", 14),
            Some("periodic-script")
        );
    }

    #[test]
    fn shell_profile_injection() {
        assert_eq!(classify(b"/Users/test/.zshrc", 14), Some("shell-profile"));
        assert_eq!(classify(b"/Users/test/.bashrc", 14), Some("shell-profile"));
        assert_eq!(
            classify(b"/Users/test/.bash_profile", 14),
            Some("shell-profile")
        );
        assert_eq!(classify(b"/Users/test/.profile", 14), Some("shell-profile"));
        assert_eq!(classify(b"/Users/test/.zshenv", 14), Some("shell-profile"));
        assert_eq!(
            classify(b"/Users/test/.zprofile", 14),
            Some("shell-profile")
        );
    }

    #[test]
    fn normal_path_not_flagged() {
        assert_eq!(classify(b"/tmp/foo.txt", 14), None);
    }

    #[test]
    fn empty_home() {
        assert_eq!(
            classify_persistence_path_with_version(
                b"/Users/test/Library/LaunchAgents/evil.plist",
                b"",
                14
            ),
            None,
        );
        assert_eq!(
            classify_persistence_path_with_version(b"/Library/LaunchAgents/evil.plist", b"", 14),
            Some("launch-agent"),
        );
    }

    #[test]
    fn version_detection_returns_plausible_value() {
        let v = macos_major_version();
        assert!((12..=30).contains(&v), "unexpected macOS major: {v}");
    }
}
