use guard_core::AuditToken;
use guard_daemon::tracked::{CoverageGap, ProcessTree, RunRecord, TreeError};

fn token(pid: u32, pidversion: u32) -> AuditToken {
    AuditToken {
        val: [0, 0, 0, 0, 0, pid, 0, pidversion],
    }
}

#[test]
fn new_tree_is_empty() {
    let t = ProcessTree::new();
    assert_eq!(t.nodes_len(), 0);
    assert_eq!(t.runs_len(), 0);
}

#[test]
fn insert_root_is_idempotent() {
    let t = ProcessTree::new();
    let r = token(100, 1);
    assert!(t.insert_root(r, "u1".into(), "/usr/bin/npm".into()));
    assert!(!t.insert_root(r, "u1".into(), "/usr/bin/npm".into())); // duplicate
    assert_eq!(t.nodes_len(), 1);
    assert!(t.is_tracked_root(&r));
    assert!(t.is_tracked(&r));
}

#[test]
fn record_fork_links_child_and_inherits_tracked_root() {
    let t = ProcessTree::new();
    let r = token(100, 1);
    let c1 = token(200, 1);
    t.insert_root(r, "u1".into(), "/usr/bin/npm".into());
    t.record_fork(r, c1).expect("fork ok");
    let n = t.get_node(&c1).expect("c1");
    assert_eq!(n.parent_audit_token, Some(r));
    assert_eq!(n.tracked_root, r);
    assert_eq!(n.run_uuid, "u1");
    assert!(!t.is_tracked_root(&c1));
    assert!(t.is_tracked(&c1));
}

#[test]
fn tree_05_grandchild_inherits_original_root() {
    // Reparenting test: r forks c1, c1 forks c2, c1 dies (kernel-side
    // reparents c2 to launchd). Stentorian Guard's `tracked_root` for c2 is r (the
    // ORIGINAL root), not c1's parent (which would be launchd post-reparent).
    let t = ProcessTree::new();
    let r = token(100, 1);
    let c1 = token(200, 1);
    let c2 = token(300, 1);
    t.insert_root(r, "u1".into(), "/usr/bin/npm".into());
    t.record_fork(r, c1).unwrap();
    t.record_fork(c1, c2).unwrap();
    let n = t.get_node(&c2).unwrap();
    assert_eq!(
        n.tracked_root, r,
        "TREE-05: grandchild's tracked_root is the original guard-run root"
    );
    assert_eq!(n.parent_audit_token, Some(c1));
    // Even if c1 disappears from the tree later (we don't model exit here),
    // c2's tracked_root remains r — the field is set at fork-time-only.
}

#[test]
fn record_fork_unknown_parent_errors() {
    let t = ProcessTree::new();
    let unknown = token(999, 1);
    let child = token(1000, 1);
    match t.record_fork(unknown, child) {
        Err(TreeError::ParentNotFound) => {}
        other => panic!("expected ParentNotFound, got {other:?}"),
    }
}

#[test]
fn record_exec_updates_binary_path() {
    let t = ProcessTree::new();
    let r = token(100, 1);
    t.insert_root(r, "u1".into(), "/usr/bin/npm".into());
    t.record_exec(r, "/usr/bin/node".into()).unwrap();
    assert_eq!(t.get_node(&r).unwrap().binary_path, "/usr/bin/node");
}

#[test]
fn set_coverage_gap_records_gap() {
    let t = ProcessTree::new();
    let r = token(100, 1);
    t.insert_root(r, "u1".into(), "/usr/bin/npm".into());
    let gap = CoverageGap::ConfirmedHardened {
        binary_path: "/usr/bin/python3".into(),
        detected_at_ms: 12345,
    };
    t.set_coverage_gap(r, gap.clone()).unwrap();
    assert_eq!(t.get_node(&r).unwrap().coverage_gap, Some(gap));
}

#[test]
fn run_records_insert_get_remove() {
    let t = ProcessTree::new();
    let rec = RunRecord {
        run_uuid: "u1".into(),
        tracked_root: token(100, 1),
        snapshot_path: "/tmp/u1.cbor".into(),
        manifest_path: "/tmp/u1.manifest".into(),
        is_tty: false,
        baseline_mode: false,
    };
    t.insert_run(rec.clone());
    let got = t.get_run("u1").expect("get");
    assert_eq!(got.run_uuid, "u1");
    let removed = t.remove_run("u1").unwrap();
    assert_eq!(removed.snapshot_path, rec.snapshot_path);
    assert!(t.get_run("u1").is_none());
}

#[test]
fn concurrent_reads_do_not_deadlock() {
    use std::sync::Arc;
    use std::thread;
    let t = Arc::new(ProcessTree::new());
    let r = token(100, 1);
    t.insert_root(r, "u1".into(), "/usr/bin/npm".into());
    let mut handles = vec![];
    for _ in 0..16 {
        let t = t.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                assert!(t.is_tracked(&r));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
