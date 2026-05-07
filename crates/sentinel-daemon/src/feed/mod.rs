//! Phase 4: Threat-intelligence feed ingestion (D-78..D-95).
//!
//! Plan 04-01 (Wave 0): cfg(test)-gated spike modules validated gix
//! shallow-clone API, panic-isolation viability, rusqlite_migration PRAGMA
//! support, and the empirical `database_specific.iocs` host-IoC signal.
//!
//! Plan 04-02 (this plan): populates this module with `store`, `parser`,
//! `matcher` (now), and `fetcher`, `concurrency` (next task).

pub mod matcher;
pub mod parser;
pub mod store;

#[cfg(test)]
mod spike_gix;
#[cfg(test)]
mod spike_panic;
#[cfg(test)]
mod spike_pragma;
#[cfg(test)]
mod spike_iocs_field;
