//! Persistence-path classifier for open/openat monitoring (M003-S04).

/// Check if `path` targets a macOS persistence location.
/// Returns the persistence category if matched, None otherwise.
///
/// `path` and `home` are raw byte slices (no NUL terminator).
/// Zero-allocation: all comparisons are bytewise on the stack.
pub fn classify_persistence_path(path: &[u8], home: &[u8]) -> Option<&'static str> {
    // ~/Library/LaunchAgents/
    if starts_with_home_then(path, home, b"/Library/LaunchAgents/") {
        return Some("launch-agent");
    }
    // /Library/LaunchAgents/
    if path.starts_with(b"/Library/LaunchAgents/") {
        return Some("launch-agent");
    }
    // /Library/LaunchDaemons/
    if path.starts_with(b"/Library/LaunchDaemons/") {
        return Some("launch-daemon");
    }
    // ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/
    if starts_with_home_then(
        path,
        home,
        b"/Library/Application Support/com.apple.backgroundtaskmanagementagent/",
    ) {
        return Some("login-item");
    }
    // crontab paths
    if path.starts_with(b"/usr/lib/cron/tabs/") || path.starts_with(b"/var/at/tabs/") {
        return Some("crontab");
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

    #[test]
    fn launch_agent_user() {
        let home = b"/Users/test";
        let path = b"/Users/test/Library/LaunchAgents/evil.plist";
        assert_eq!(classify_persistence_path(path, home), Some("launch-agent"));
    }

    #[test]
    fn launch_agent_system() {
        assert_eq!(
            classify_persistence_path(b"/Library/LaunchAgents/evil.plist", b"/Users/test"),
            Some("launch-agent"),
        );
    }

    #[test]
    fn launch_daemon() {
        assert_eq!(
            classify_persistence_path(b"/Library/LaunchDaemons/evil.plist", b"/Users/test"),
            Some("launch-daemon"),
        );
    }

    #[test]
    fn login_item() {
        let path = b"/Users/test/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm";
        assert_eq!(
            classify_persistence_path(path, b"/Users/test"),
            Some("login-item"),
        );
    }

    #[test]
    fn crontab() {
        assert_eq!(
            classify_persistence_path(b"/usr/lib/cron/tabs/root", b"/Users/test"),
            Some("crontab"),
        );
        assert_eq!(
            classify_persistence_path(b"/var/at/tabs/user", b"/Users/test"),
            Some("crontab"),
        );
    }

    #[test]
    fn normal_path_not_flagged() {
        assert_eq!(
            classify_persistence_path(b"/tmp/foo.txt", b"/Users/test"),
            None,
        );
    }

    #[test]
    fn empty_home() {
        assert_eq!(
            classify_persistence_path(b"/Users/test/Library/LaunchAgents/evil.plist", b""),
            None,
        );
        // System paths still work
        assert_eq!(
            classify_persistence_path(b"/Library/LaunchAgents/evil.plist", b""),
            Some("launch-agent"),
        );
    }
}
