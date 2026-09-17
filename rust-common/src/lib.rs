//! Shared common utilities for CoFHE Rust services

pub mod logger;

// Re-export log crate for use by dependent crates
pub use log;

#[cfg(feature = "keygen")]
pub mod keygen;

#[cfg(feature = "signing")]
pub mod signing;

#[cfg(feature = "safe-serde")]
pub mod safe_serde;
