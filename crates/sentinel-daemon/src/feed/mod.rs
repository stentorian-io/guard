//! Phase 4: Threat-intelligence feed ingestion (D-78..D-95).
//!
//! Plan 04-01 (this plan): Wave 0 spikes validating gix shallow-clone API,
//! panic-isolation viability, rusqlite_migration PRAGMA support, and the
//! empirical `database_specific.iocs` host-IoC signal.
//!
//! Plan 04-02 will populate this module with `fetcher`, `parser`, `matcher`,
//! `store`, and `concurrency` submodules. Until then this file holds only
//! the spike modules (`#[cfg(test)] mod spike_*`).

#[cfg(test)]
mod spike_gix;
#[cfg(test)]
mod spike_panic;
#[cfg(test)]
mod spike_pragma;
#[cfg(test)]
mod spike_iocs_field;
