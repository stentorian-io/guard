use guard_core::AuditToken;
use guard_daemon::log_writer::package_context::{
    infer_package_context_with_retry, package_context_from_pm_env,
};
use guard_daemon::tracked::ProcessTree;
use std::sync::Arc;
use std::time::Duration;

fn pair(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

#[test]
fn npm_package_with_lifecycle() {
    let env = vec![
        pair("npm_package_name", "lodash"),
        pair("npm_package_version", "4.17.21"),
        pair("npm_lifecycle_event", "postinstall"),
    ];
    let ctx = package_context_from_pm_env(&env, "npm install lodash").expect("ctx");
    assert_eq!(ctx.ecosystem, "npm");
    assert_eq!(ctx.package, "lodash");
    assert_eq!(ctx.version, "4.17.21");
    assert_eq!(ctx.lifecycle.as_deref(), Some("postinstall"));
    assert_eq!(ctx.root_command, "npm install lodash");
}

#[test]
fn cargo_package_no_lifecycle() {
    let env = vec![
        pair("CARGO_PKG_NAME", "stt-guard"),
        pair("CARGO_PKG_VERSION", "0.3.0"),
    ];
    let ctx = package_context_from_pm_env(&env, "cargo build").expect("ctx");
    assert_eq!(ctx.ecosystem, "cargo");
    assert_eq!(ctx.package, "stt-guard");
    assert_eq!(ctx.lifecycle, None);
}

#[test]
fn empty_env_returns_none() {
    assert!(package_context_from_pm_env(&[], "x").is_none());
}

#[test]
fn unrelated_env_returns_none() {
    let env = vec![pair("HOME", "/x"), pair("PATH", "/y")];
    assert!(package_context_from_pm_env(&env, "x").is_none());
}

#[test]
fn npm_takes_priority_over_other_signals() {
    // Mixed env (rare but possible): npm wins because tested first.
    let env = vec![
        pair("CARGO_PKG_NAME", "rust-side"),
        pair("npm_package_name", "node-side"),
    ];
    let ctx = package_context_from_pm_env(&env, "x").expect("ctx");
    assert_eq!(ctx.ecosystem, "npm");
    assert_eq!(ctx.package, "node-side");
}

#[test]
fn root_command_truncated() {
    let env = vec![pair("npm_package_name", "x")];
    let long = "a".repeat(500);
    let ctx = package_context_from_pm_env(&env, &long).expect("ctx");
    assert!(ctx.root_command.len() <= 256);
}

#[test]
fn retry_waits_for_pm_env_snapshot() {
    let tree = Arc::new(ProcessTree::new());
    let token = AuditToken {
        val: [0, 0, 0, 0, 0, 42, 0, 7],
    };
    tree.insert_root(token, "run".into(), "node".into());

    let setter_tree = Arc::clone(&tree);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(25));
        setter_tree.set_pm_env_snapshot(
            &token,
            vec![
                pair("npm_package_name", "ua-parser-js"),
                pair("npm_package_version", "0.7.29"),
            ],
        );
    });

    let ctx =
        infer_package_context_with_retry(&tree, &token, "npm install", Duration::from_millis(250))
            .expect("ctx");
    assert_eq!(ctx.package, "ua-parser-js");
    assert_eq!(ctx.version, "0.7.29");
}

#[test]
fn writer_handle_send_does_not_block() {
    use guard_daemon::log_writer::{
        Decision, JSONL_SCHEMA_VERSION, LogRow, LogWriter, ProcessCtxLog, RootCtxLog, now_rfc3339,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("stt-guard.log");
    let writer = LogWriter::spawn(log.clone()).expect("spawn");
    let ctx = ProcessCtxLog {
        pid: 1,
        pidversion: 1,
        argv: vec!["x".into()],
        cwd: "/tmp".into(),
    };
    let root = RootCtxLog {
        audit_token: [0; 8],
        argv: vec!["x".into()],
    };
    let dec = Decision {
        schema_version: JSONL_SCHEMA_VERSION,
        ts: now_rfc3339(),
        verdict: "Deny",
        dest_host: "h".into(),
        dest_port: 1,
        dest_ip: None,
        run_uuid: "r".into(),
        source_kind: "k".into(),
        source_locator: None,
        process: ctx.clone(),
        parent: ctx,
        root,
        package_context: None,
        intel: None,
    };
    writer.send(LogRow::Block(dec));
    // Wait briefly for the writer thread to drain.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let bytes = std::fs::read(&log).expect("read");
    assert!(!bytes.is_empty());
    assert!(bytes.windows(7).any(|w| w == b"\"event\""));
    let (b, a, g) = writer.counters_snapshot();
    assert_eq!((b, a, g), (1, 0, 0));
}
