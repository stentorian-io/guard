-- v0.3 — install_artifacts table.
--
-- Records every modification made by `sentinel install` so that
-- `sentinel uninstall` can reverse each artifact precisely.
--
-- artifact_kind values:
--   launchagent      — ~/Library/LaunchAgents/com.sentinel.daemon.plist
--   marker_block     — one row per modified rc file (~/.zshrc, ~/.bashrc, ...)
--   init_script      — ~/.config/sentinel/init.sh
--   state_dir        — ~/Library/Application Support/Sentinel/
--   log_dir          — ~/Library/Logs/Sentinel/
--   binary           — informational ($(brew --prefix)/bin/sentinel etc.; never deleted by uninstall)

CREATE TABLE IF NOT EXISTS install_artifacts (
    artifact_kind     TEXT    NOT NULL CHECK (artifact_kind IN ('launchagent','marker_block','init_script','state_dir','log_dir','binary')),
    target_path       TEXT    NOT NULL,
    content_hash      TEXT,
    installed_at      INTEGER NOT NULL,
    sentinel_version  TEXT    NOT NULL,
    PRIMARY KEY (artifact_kind, target_path)
);
