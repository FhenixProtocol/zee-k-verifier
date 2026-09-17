use rust_common::signing::SigningError;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("Failed to verify ZK proof: {0}")]
    ProofVerificationError(String),

    #[error("Invalid signature: {0}")]
    SignatureError(#[from] k256::ecdsa::Error),

    #[error("Invalid hex input: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("TFHE error: {0}")]
    TfheError(#[from] tfhe::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),
}

pub type Result<T> = std::result::Result<T, VerifierError>;
