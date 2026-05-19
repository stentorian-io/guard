//! crates/sentinel-cli/src/prompt_render.rs
//!
//! TTY rendering of PromptRequest + 3-way [1/2/3] choice.

use std::io::{BufRead, Write};

use sentinel_ipc::{IPC_SCHEMA_V3, PromptRequest, PromptResponse, PromptVerdict, RulePattern};

use crate::CliError;

/// Render a PromptRequest to stdout and read the user's 3-way choice from stdin.
/// Blocks until the user enters a valid choice (1/2/3) or ? for help.
///
/// Returns the PromptResponse (with the user's verdict and optional rule_pattern).
pub fn render_and_choose(req: &PromptRequest) -> Result<PromptResponse, CliError> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out).ok();
    writeln!(
        out,
        "  Sentinel: outbound to {}:{} (source: {})",
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
                    m.advisory_id,
                    m.feed
                ).ok();
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
                "".to_string()
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
            writeln!(
                out,
                "    [{}] {} {}",
                i + 1,
                r.match_type,
                r.pattern,
            )
            .ok();
        }
    }
    writeln!(
        out,
        "  Choose: [1]once  [2]always  [3]deny  [?]help"
    )
    .ok();
    out.flush().ok();
    drop(out);

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
                println!("  [2] allow always — write to SQLite rules (requires Touch ID / password)");
                println!("  [3] deny — connection blocked, logged");
                continue;
            }
            _ => {
                println!("  invalid choice; pick 1/2/3 or ?");
                continue;
            }
        };
        let verdict = if matches!(verdict, PromptVerdict::AllowOnce | PromptVerdict::AllowAlwaysMachine) {
            let reason = format!(
                "Sentinel: approve outbound to {}:{}",
                req.dest_host, req.dest_port
            );
            if crate::biometric::authenticate(&reason) {
                verdict
            } else {
                println!("  authentication failed — treating as deny");
                PromptVerdict::Deny
            }
        } else {
            verdict
        };
        let rule_pattern = match verdict {
            PromptVerdict::AllowAlwaysMachine => {
                req.suggested_rules.first().map(|r| RulePattern {
                    match_type: r.match_type.clone(),
                    pattern: r.pattern.clone(),
                })
            }
            _ => None,
        };
        return Ok(PromptResponse {
            schema_version: IPC_SCHEMA_V3,
            prompt_id: req.prompt_id.clone(),
            verdict,
            rule_pattern,
        });
    }
}
