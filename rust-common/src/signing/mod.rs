//! ECDSA signing utilities for CoFHE services
//!
//! This module provides ECDSA secp256k1 signing functionality compatible with EVM.
//! It uses Keccak256 for message hashing and BIP-62 signature normalization.

mod error;
mod evm_address;
mod message_builder;
mod signer;

pub use error::SigningError;
pub use evm_address::EvmAddress;
pub use message_builder::{SigningEncode, SigningMessageBuilder};
pub use signer::{SignatureVFormat, Signer};

// Re-export k256 types that users may need
pub use k256::ecdsa::{RecoveryId, Signature, SigningKey};
