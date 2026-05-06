//! crates/sentinel-cli/src/prompt_render.rs
//!
//! Phase 3 plan 03-12 — TTY rendering of PromptRequest + 4-way [1/2/3/4] choice.

use std::io::{BufRead, Write};

use sentinel_ipc::{IPC_SCHEMA_V3, PromptRequest, PromptResponse, PromptVerdict, RulePattern};

use crate::CliError;

/// Render a PromptRequest to stdout and read the user's 4-way choice from stdin.
/// Blocks until the user enters a valid choice (1/2/3/4) or ? for help.
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
                "    [{}] {} {} ({})",
                i + 1,
                r.match_type,
                r.pattern,
                r.scope_hint
            )
            .ok();
        }
    }
    writeln!(
        out,
        "  Choose: [1]once  [2]always-machine  [3]always-project  [4]deny  [?]help"
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
            "3" => PromptVerdict::AllowAlwaysProject,
            "4" => PromptVerdict::Deny,
            "?" => {
                println!("  [1] allow this connection once (no rule written)");
                println!("  [2] allow always — write to machine-wide SQLite rules");
                println!("  [3] allow always — append to .sentinel.toml + auto-trust");
                println!("  [4] deny — connection blocked, logged");
                continue;
            }
            _ => {
                println!("  invalid choice; pick 1/2/3/4 or ?");
                continue;
            }
        };
        let rule_pattern = match verdict {
            PromptVerdict::AllowAlwaysMachine | PromptVerdict::AllowAlwaysProject => {
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
