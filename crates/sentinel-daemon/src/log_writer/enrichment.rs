//! Feed-based log enrichment was removed when OTA feed fetching was replaced
//! with build-time-embedded rules. This module is retained as a stub so
//! callers compile without conditional compilation.

use sentinel_ipc::{IntelMatch, PackageContext};

pub fn enrich(_pkg: &PackageContext) -> Vec<IntelMatch> {
    Vec::new()
}

pub fn enrich_for_host(_host: &str) -> Vec<IntelMatch> {
    Vec::new()
}
