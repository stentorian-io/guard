//! Sentinel domain errors.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("snapshot codec: {0}")]
    Codec(String),
    #[error("snapshot schema version mismatch: expected {expected}, got {got}")]
    SchemaVersionMismatch { expected: u16, got: u16 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Codec(e.to_string())
    }
}

impl<E: std::fmt::Debug> From<ciborium::de::Error<E>> for Error {
    fn from(e: ciborium::de::Error<E>) -> Self {
        Error::Codec(e.to_string())
    }
}
