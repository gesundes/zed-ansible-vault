use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    User(String),
    #[error("Operation cancelled")]
    Cancelled,
    #[error("The operation timed out")]
    Timeout,
    #[error("The document changed while the operation was running; retry the action")]
    StaleDocument,
    #[error("Ansible Vault rejected the password or encrypted data")]
    VaultRejected,
    #[error("A filesystem operation failed: {0}")]
    Filesystem(String),
    #[error("An internal extension error occurred")]
    Internal(#[source] anyhow::Error),
}

impl AppError {
    pub fn user(message: impl Into<String>) -> Self {
        Self::User(message.into())
    }

    pub fn filesystem(error: impl std::fmt::Display) -> Self {
        Self::Filesystem(error.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}
