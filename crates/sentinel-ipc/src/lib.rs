//! Sentinel IPC: length-prefixed CBOR over Unix sockets with peer audit-token auth.
//! Plan 04 fills in the real implementations.

pub mod frame {}
pub mod messages {}
pub mod transport {}
