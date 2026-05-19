//! `sentinel status advisory <ID>` — look up threat-intel advisory details.

use crate::CliError;
use sentinel_daemon::curated;

pub fn run(advisory_id: &str, json: bool) -> Result<i32, CliError> {
    let entries = curated::load_curated()
        .map_err(|e| CliError::Other(format!("failed to load curated rules: {e}")))?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.reason.contains(advisory_id))
        .collect();

    if matches.is_empty() {
        if json {
            println!("{{\"advisory_id\":{},\"matches\":[]}}", serde_json::json!(advisory_id));
        } else {
            eprintln!("No entries found for advisory {advisory_id}");
        }
        return Ok(1);
    }

    if json {
        let rows: Vec<_> = matches
            .iter()
            .map(|e| {
                serde_json::json!({
                    "kind": format!("{:?}", e.kind),
                    "tier": format!("{:?}", e.tier),
                    "match_type": format!("{:?}", e.match_type),
                    "pattern": e.pattern,
                    "reason": e.reason,
                })
            })
            .collect();
        let out = serde_json::json!({
            "advisory_id": advisory_id,
            "matches": rows,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Advisory: {advisory_id}");
        println!("Matching rules ({}):", matches.len());
        println!();
        for e in &matches {
            println!("  tier:    {:?}", e.tier);
            println!("  match:   {:?} {}", e.match_type, e.pattern);
            println!("  reason:  {}", e.reason);
            println!();
        }
    }

    Ok(0)
}
