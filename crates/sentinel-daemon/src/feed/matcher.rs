//! Re-export shim — the OSV version-range matcher lives in
//! `sentinel_core::osv_match` for cross-crate testability + reuse. This
//! module exists so callers within `sentinel-daemon` see a `feed::matcher::*`
//! import path consistent with the daemon-side feed/ module layout.

pub use sentinel_core::osv_match::{
    version_in_affected_block, version_in_range, Event, Range, RangeType,
};
