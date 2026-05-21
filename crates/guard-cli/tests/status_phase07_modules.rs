use guard_cli::CliError;
use guard_cli::status::run_status;
use guard_cli::status::{denials, review, rules};
use std::path::Path;

#[test]
fn status_rules_run_signature_pinned() {
    let _: fn(
        &Path,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    ) -> Result<i32, CliError> = rules::run;
}

#[test]
fn status_denials_run_signature_pinned() {
    let _: fn(&str) -> Result<i32, CliError> = denials::run;
}

#[test]
fn status_review_run_signature_pinned() {
    let _: fn(&Path, Option<String>) -> Result<i32, CliError> = review::run;
}

#[test]
fn status_run_status_still_reachable() {
    let _: fn(&Path, &Path) -> Result<i32, CliError> = run_status;
}
