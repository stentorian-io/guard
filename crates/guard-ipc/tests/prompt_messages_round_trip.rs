//! v0.3: round-trip Serialize+Deserialize tests for new IPC types.
use guard_ipc::*;

fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
    t: &T,
) {
    let mut bytes = Vec::new();
    ciborium::into_writer(t, &mut bytes).expect("encode");
    let decoded: T = ciborium::from_reader(bytes.as_slice()).expect("decode");
    assert_eq!(&decoded, t);
}

#[test]
fn status_round_trip() {
    round_trip(&Status::new());
}

#[test]
fn status_reply_ok_round_trip() {
    let r = StatusReply::ok(
        DaemonStateKind::Operational,
        vec![],
        vec![],
        StatusCounters {
            rules_user: 0,
            blocks_today: 0,
            allows_today: 0,
            gaps_today: 0,
        },
        None,
        None,
    );
    round_trip(&r);
}

#[test]
fn status_reply_err_round_trip() {
    round_trip(&StatusReply::err("test error"));
}

#[test]
fn prompt_channel_init_round_trip() {
    round_trip(&PromptChannelInit {
        schema_version: IPC_SCHEMA_V3,
        run_uuid: "abc-123".into(),
    });
}

#[test]
fn prompt_channel_init_ack_round_trip() {
    round_trip(&PromptChannelInitAck::ok());
    round_trip(&PromptChannelInitAck::err("bad uuid"));
}

#[test]
fn prompt_request_round_trip() {
    let r = PromptRequest {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: "p1".into(),
        dest_host: "evil.example.com".into(),
        dest_port: 443,
        dest_ip: None,
        source_kind: "default_deny".into(),
        source_locator: None,
        package_context: Some(PackageContext {
            ecosystem: "npm".into(),
            package: "lodash".into(),
            version: "4.17.21".into(),
            lifecycle: Some("postinstall".into()),
            root_command: "npm install".into(),
        }),
        process: ProcessCtx {
            pid: 1,
            pidversion: 1,
            argv0: "node".into(),
            cwd: "/tmp".into(),
        },
        intel: None,
        suggested_rules: vec![SuggestedRule {
            match_type: "exact".into(),
            pattern: "evil.example.com".into(),
        }],
    };
    round_trip(&r);
}

#[test]
fn prompt_response_round_trip() {
    round_trip(&PromptResponse {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: "p1".into(),
        verdict: PromptVerdict::AllowAlwaysMachine,
        rule_pattern: Some(RulePattern {
            match_type: "exact".into(),
            pattern: "h".into(),
        }),
        signed_rule: None,
    });
}

#[test]
fn prompt_cancel_round_trip() {
    round_trip(&PromptCancel {
        schema_version: IPC_SCHEMA_V3,
        prompt_id: "p1".into(),
    });
}

#[test]
fn insert_user_rule_round_trip() {
    round_trip(&InsertUserRule {
        schema_version: IPC_SCHEMA_V5,
        kind: "allow".into(),
        match_type: "exact".into(),
        pattern: "h".into(),
        reason: "user-approved".into(),
        created_at_unix_ms: 1_700_000_000_000,
        origin: "test".into(),
        run_uuid: Some("r1".into()),
        signature: None,
    });
    round_trip(&InsertUserRuleReply::ok(42));
    round_trip(&InsertUserRuleReply::err("bad"));
}

#[test]
fn read_install_artifacts_round_trip() {
    round_trip(&ReadInstallArtifacts::new());
    round_trip(&ReadInstallArtifactsReply::ok(vec![InstallArtifact {
        artifact_kind: "binary".into(),
        target_path: "/opt/homebrew/bin/stt-guard".into(),
        installed_at_ms: 1_700_000_000_000,
        content_hash: None,
        guard_version: "0.3.0".into(),
    }]));
    round_trip(&ReadInstallArtifactsReply::err("daemon down"));
}

#[test]
fn baseline_commit_round_trip() {
    round_trip(&BaselineCommit {
        schema_version: IPC_SCHEMA_V3,
        run_uuid: "r1".into(),
    });
    round_trip(&BaselineCommitReply::ok(vec![ProposedRule {
        match_type: "suffix".into(),
        pattern: ".s3.amazonaws.com".into(),
        reason: "baseline: ...".into(),
    }]));
}

#[test]
fn status_reply_full_ok_round_trip() {
    let r = StatusReply::ok(
        DaemonStateKind::Degraded,
        vec![TrackedRootInfo {
            run_uuid: "run-1".into(),
            audit_token: AuditTokenWire { val: [0u32; 8] },
            argv: vec!["npm".into(), "install".into()],
            started_at_ms: 1_700_000_000_000,
        }],
        vec![GapInfo {
            run_uuid: "run-1".into(),
            gap_kind: "hardened-runtime".into(),
            binary_path: Some("/usr/bin/python3".into()),
            detected_at_ms: 1_700_000_001_000,
        }],
        StatusCounters {
            rules_user: 5,
            blocks_today: 3,
            allows_today: 100,
            gaps_today: 1,
        },
        Some(InstallInfo {
            version: "0.3.0".into(),
            installed_at_ms: 1_700_000_000_000,
            artifacts: vec![InstallArtifact {
                artifact_kind: "launchagent".into(),
                target_path: "~/Library/LaunchAgents/io.stentorian.guard.agent.plist".into(),
                installed_at_ms: 1_700_000_000_000,
                content_hash: Some("abc123".into()),
                guard_version: "0.3.0".into(),
            }],
        }),
        Some(SigningInfo {
            configured: true,
            status: "configured".into(),
            signer_kind: Some("secure-enclave".into()),
            fingerprint: Some("abc123".into()),
            trust_root_path: Some("/usr/local/libexec/stt-guard/trusted-rule-signers.tsv".into()),
            trust_root_ok: true,
            reason: None,
            action: None,
        }),
    );
    round_trip(&r);
}

#[test]
fn disable_curated_rule_round_trip() {
    round_trip(&DisableCuratedRule::new(
        "registry.npmjs.org",
        "suspected compromise",
    ));
    round_trip(&DisableCuratedRuleReply::ok());
    round_trip(&DisableCuratedRuleReply::err("no curated rule matches"));
}

#[test]
fn enable_curated_rule_round_trip() {
    round_trip(&EnableCuratedRule::new("registry.npmjs.org"));
    round_trip(&EnableCuratedRuleReply::ok(true));
    round_trip(&EnableCuratedRuleReply::ok(false));
    round_trip(&EnableCuratedRuleReply::err("pattern must be non-empty"));
}
