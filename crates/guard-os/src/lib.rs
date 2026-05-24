//! OS-specific primitives behind explicit capability APIs.
//!
//! This crate centralizes direct OS calls so higher-level crates do not spread
//! Darwin/Linux conditionals through domain and orchestration logic.

pub mod error;
pub mod peer;

pub use error::OsError;
