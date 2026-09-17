use strum::IntoStaticStr;
use thiserror::Error;

/// Errors that can occur during object storage operations
#[derive(Error, Debug, IntoStaticStr)]
pub enum StorageError {
    /// Invalid configuration
    #[error("Configuration error: {0}")]
    #[strum(serialize = "configuration")]
    Configuration(String),

    /// Network-related errors (connectivity, DNS, etc.)
    #[error("Network error: {0}")]
    #[strum(serialize = "network")]
    Network(String),

    /// Operation timed out
    #[error("Operation timed out after {timeout_secs}s: {operation}")]
    #[strum(serialize = "timeout")]
    Timeout { operation: String, timeout_secs: u64 },

    /// Permission/authentication errors
    #[error("Permission denied: {0}")]
    #[strum(serialize = "permission_denied")]
    PermissionDenied(String),

    /// Object not found
    #[error("Object not found: {0}")]
    #[strum(serialize = "not_found")]
    NotFound(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    #[strum(serialize = "serialization")]
    Serialization(String),

    /// Generic storage backend error (catch-all)
    #[error("Storage error: {0}")]
    #[strum(serialize = "generic")]
    Generic(String),
}

impl StorageError {
    /// Check if error is retryable (for retry logic)
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            StorageError::Network(_) | StorageError::Timeout { .. } | StorageError::Generic(_)
        )
    }
}

/// Result type alias for storage operations
pub type StorageResult<T> = Result<T, StorageError>;
