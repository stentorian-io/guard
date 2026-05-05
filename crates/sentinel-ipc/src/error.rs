//! sentinel-ipc errors.

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame too large: {got} bytes (max {max})")]
    FrameTooLarge { got: u32, max: u32 },

    #[error("codec: {0}")]
    Codec(String),

    #[error("schema mismatch: expected {expected}, got {got}")]
    SchemaMismatch { expected: u16, got: u16 },

    #[error("peer auth failed: {0}")]
    PeerAuth(String),
}

impl IpcError {
    pub fn codec<E: std::fmt::Display>(e: E) -> Self {
        Self::Codec(e.to_string())
    }
}
