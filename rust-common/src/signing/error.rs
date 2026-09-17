//! Error types for the signing module

use thiserror::Error;

/// Errors that can occur during signing operations
#[derive(Debug, Error)]
pub enum SigningError {
    /// Failed to parse the signing key
    #[error("Invalid signing key: {0}")]
    InvalidKey(String),

    /// Failed to sign the message
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Failed to read key file
    #[error("Failed to read key file: {0}")]
    KeyFileError(String),

    /// Failed to decode hex
    #[error("Failed to decode hex: {0}")]
    HexDecodeError(String),
}

impl From<k256::ecdsa::Error> for SigningError {
    fn from(err: k256::ecdsa::Error) -> Self {
        SigningError::SigningFailed(err.to_string())
    }
}

impl From<hex::FromHexError> for SigningError {
    fn from(err: hex::FromHexError) -> Self {
        SigningError::HexDecodeError(err.to_string())
    }
}

impl From<std::io::Error> for SigningError {
    fn from(err: std::io::Error) -> Self {
        SigningError::KeyFileError(err.to_string())
    }
}
