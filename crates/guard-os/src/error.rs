#[derive(Debug, thiserror::Error)]
pub enum OsError {
    #[error("{capability} is unsupported on {target}")]
    Unsupported {
        capability: &'static str,
        target: &'static str,
    },

    #[error("{capability} failed: {source}")]
    Io {
        capability: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("{capability} returned unexpected data: {detail}")]
    UnexpectedData {
        capability: &'static str,
        detail: String,
    },
}

impl OsError {
    #[must_use]
    pub const fn unsupported(capability: &'static str) -> Self {
        Self::Unsupported {
            capability,
            target: std::env::consts::OS,
        }
    }

    #[must_use]
    pub fn io(capability: &'static str, source: std::io::Error) -> Self {
        Self::Io { capability, source }
    }

    pub fn unexpected_data(capability: &'static str, detail: impl Into<String>) -> Self {
        Self::UnexpectedData {
            capability,
            detail: detail.into(),
        }
    }
}
