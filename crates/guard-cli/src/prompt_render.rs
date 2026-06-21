//! crates/guard-cli/src/prompt_render.rs
//!
//! TTY rendering of `PromptRequest` + 3-way [1/2/3] choice.

use std::io::{BufRead, Write};

use guard_ipc::{
    IPC_SCHEMA_V3, IPC_SCHEMA_V5, PromptRequest, PromptResponse, PromptVerdict, RulePattern,
};

use crate::CliError;

/// Render a `PromptRequest` to stdout and read the user's 3-way choice from stdin.
/// Blocks until the user enters a valid choice (1/2/3) or ? for help.
///
/// Returns the `PromptResponse` (with the user's verdict and optional `rule_pattern`).
///
/// # Errors
///
/// Returns stdin read errors or rule-signing errors for persistent allow
/// choices.
pub fn render_and_choose(req: &PromptRequest, run_uuid: &str) -> Result<PromptResponse, CliError> {
    render_prompt(req);

    let verdict = read_prompt_verdict()?;
    let verdict = authenticate_allow_choice(req, verdict);
    let rule_pattern = rule_pattern_for_verdict(req, &verdict);
    let signed_rule = signed_rule_for_verdict(run_uuid, &verdict, rule_pattern.as_ref())?;

    Ok(PromptResponse {
        schema_version: if signed_rule.is_some() {
            IPC_SCHEMA_V5
        } else {
            IPC_SCHEMA_V3
        },
        prompt_id: req.prompt_id.clone(),
        verdict,
        rule_pattern,
        signed_rule,
    })
}

fn render_prompt(req: &PromptRequest) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out).ok();
    writeln!(
        out,
        "  Stentorian Guard: outbound to {}:{} (source: {})",
        req.dest_host, req.dest_port, req.source_kind
    )
    .ok();
    if let Some(loc) = &req.source_locator {
        writeln!(out, "    locator: {loc}").ok();
    }
    if let Some(intel) = &req.intel {
        for m in intel {
            let qualifier = m.tag.as_deref().unwrap_or("unknown");
            if qualifier == "suspect" {
                writeln!(
                    out,
                    "  \x1b[33mWARNING: suspicious host ({}) — not yet confirmed malicious, approval at own risk\x1b[0m",
                    m.advisory_id
                ).ok();
            } else {
                writeln!(
                    out,
                    "  \x1b[31mBLOCKED: known malicious host ({}) — advisory: {}\x1b[0m",
                    m.advisory_id, m.feed
                )
                .ok();
            }
        }
    }
    if let Some(pkg) = &req.package_context {
        writeln!(
            out,
            "    package: {} {}@{} ({}{})",
            pkg.ecosystem,
            pkg.package,
            pkg.version,
            pkg.lifecycle.as_deref().unwrap_or("-"),
            if pkg.root_command.is_empty() {
                String::new()
            } else {
                format!(", {}", pkg.root_command)
            }
        )
        .ok();
    }
    writeln!(
        out,
        "  process: pid={} argv0={} cwd={}",
        req.process.pid, req.process.argv0, req.process.cwd
    )
    .ok();
    if !req.suggested_rules.is_empty() {
        writeln!(out, "  suggested:").ok();
        for (i, r) in req.suggested_rules.iter().enumerate().take(3) {
            writeln!(out, "    [{}] {} {}", i + 1, r.match_type, r.pattern).ok();
        }
    }
    writeln!(out, "  Choose: [1]once  [2]always  [3]deny  [?]help").ok();
    out.flush().ok();
}

fn read_prompt_verdict() -> Result<PromptVerdict, CliError> {
    loop {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::Other(format!("stdin: {e}")))?;
        let choice = line.trim();
        let verdict = match choice {
            "1" => PromptVerdict::AllowOnce,
            "2" => PromptVerdict::AllowAlwaysMachine,
            "3" => PromptVerdict::Deny,
            "?" => {
                println!("  [1] allow this connection once (requires Touch ID / password)");
                println!(
                    "  [2] allow always — write to SQLite rules (requires Touch ID / password)"
                );
                println!("  [3] deny — connection blocked, logged");
                continue;
            }
            _ => {
                println!("  invalid choice; pick 1/2/3 or ?");
                continue;
            }
        };

        return Ok(verdict);
    }
}

fn authenticate_allow_choice(req: &PromptRequest, verdict: PromptVerdict) -> PromptVerdict {
    if !matches!(
        verdict,
        PromptVerdict::AllowOnce | PromptVerdict::AllowAlwaysMachine
    ) {
        return verdict;
    }

    let reason = allow_choice_authentication_reason(req);
    if crate::biometric::authenticate(&reason) {
        verdict
    } else {
        println!("  authentication failed — treating as deny");
        PromptVerdict::Deny
    }
}

fn allow_choice_authentication_reason(req: &PromptRequest) -> String {
    format!("approve outbound to {}", req.dest_host)
}

fn rule_pattern_for_verdict(req: &PromptRequest, verdict: &PromptVerdict) -> Option<RulePattern> {
    match verdict {
        PromptVerdict::AllowAlwaysMachine => req.suggested_rules.first().map(|r| RulePattern {
            match_type: r.match_type.clone(),
            pattern: r.pattern.clone(),
        }),
        _ => None,
    }
}

fn signed_rule_for_verdict(
    run_uuid: &str,
    verdict: &PromptVerdict,
    rule_pattern: Option<&RulePattern>,
) -> Result<Option<guard_ipc::InsertUserRule>, CliError> {
    let (PromptVerdict::AllowAlwaysMachine, Some(rule_pattern)) = (verdict, rule_pattern) else {
        return Ok(None);
    };

    let created_at_unix_ms = unix_ms_now();
    let reason = format!("user-approved via prompt run {run_uuid}");
    let payload = guard_core::RuleSignaturePayloadV1::new(
        "allow",
        rule_pattern.match_type.clone(),
        rule_pattern.pattern.clone(),
        reason.clone(),
        created_at_unix_ms,
        "prompt",
        Some(run_uuid.to_string()),
    );
    let signature = crate::rule_signing::sign_rule_payload(&payload)?;

    Ok(Some(guard_ipc::InsertUserRule {
        schema_version: IPC_SCHEMA_V5,
        kind: "allow".into(),
        match_type: rule_pattern.match_type.clone(),
        pattern: rule_pattern.pattern.clone(),
        reason,
        created_at_unix_ms,
        origin: "prompt".into(),
        run_uuid: Some(run_uuid.to_string()),
        signature: Some(signature),
    }))
}

fn unix_ms_now() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_ipc::{ProcessCtx, SuggestedRule};

    #[test]
    fn allow_choice_authentication_reason_reads_after_macos_prefix() {
        let req = PromptRequest {
            schema_version: IPC_SCHEMA_V3,
            prompt_id: "prompt-1".to_string(),
            dest_host: "example.com".to_string(),
            dest_port: 0,
            dest_ip: None,
            source_kind: "unknown".to_string(),
            source_locator: None,
            package_context: None,
            process: ProcessCtx {
                pid: 1,
                pidversion: 0,
                argv0: "node".to_string(),
                cwd: "/tmp".to_string(),
            },
            intel: None,
            suggested_rules: vec![SuggestedRule {
                match_type: "exact".to_string(),
                pattern: "example.com".to_string(),
            }],
        };

        assert_eq!(
            allow_choice_authentication_reason(&req),
            "approve outbound to example.com"
        );
    }
}
