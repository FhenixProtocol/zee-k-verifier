//! Core ECDSA signer implementation

use crate::log::{debug, trace};
use k256::{
    ecdsa::{RecoveryId, Signature, SigningKey},
    elliptic_curve::scalar::IsHigh,
};
use sha3::{Digest, Keccak256};
use std::path::Path;

use super::error::SigningError;

/// Offset to convert raw recovery ID (0-3) to EVM-compatible format (27-28)
/// This is the standard offset used in Ethereum's ecrecover function
const EVM_RECOVERY_ID_OFFSET: u8 = 27;

/// Format for the signature's recovery ID (v value)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureVFormat {
    /// Raw k256 recovery ID format (0-3)
    #[default]
    Raw,
    /// EVM-compatible format (27-28), as expected by OpenZeppelin ECDSA.recover
    Evm,
}

impl SignatureVFormat {
    /// Convert a raw recovery ID byte (0-3) to the appropriate format
    pub fn convert_v(&self, raw_v: u8) -> u8 {
        match self {
            Self::Raw => raw_v,
            Self::Evm => raw_v + EVM_RECOVERY_ID_OFFSET,
        }
    }
}

impl std::str::FromStr for SignatureVFormat {
    type Err = ();

    /// Parse from string. Returns `Raw` for any unrecognized value.
    ///
    /// - "evm" (case-insensitive) -> `Evm`
    /// - anything else -> `Raw`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "evm" => Self::Evm,
            _ => Self::Raw,
        })
    }
}

/// ECDSA signer for secp256k1 signatures
///
/// This signer produces signatures compatible with EVM ecrecover:
/// - Uses Keccak256 for message hashing
/// - Applies BIP-62 signature normalization (low-S)
/// - Returns 64-byte signature + 1-byte recovery ID
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Create a new signer from a signing key
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Load a signer from a binary key file (32 bytes)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SigningError> {
        trace!("Loading binary key file");
        let key_bytes = std::fs::read(path)?;
        Self::from_bytes(&key_bytes)
    }

    /// Create a signer from raw key bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        trace!("Creating signer from {} bytes", bytes.len());
        let signing_key =
            SigningKey::from_slice(bytes).map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Compute Keccak256 hash of arbitrary data
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        Keccak256::digest(data).into()
    }

    /// Sign a pre-computed hash with BIP-62 normalization
    ///
    /// Returns the signature and recovery ID.
    /// The signature is normalized to have a low S value.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<(Signature, RecoveryId), SigningError> {
        let (sig, recid) = self.signing_key.sign_prehash_recoverable(hash)?;

        // Normalize signature (BIP-62: https://bips.dev/62/)
        // Implementation taken from the official k256 crate:
        // https://github.com/RustCrypto/elliptic-curves/blob/k256/v0.13.4/k256/src/ecdsa.rs#L193-L195
        let is_y_odd = recid.is_y_odd() ^ bool::from(sig.s().is_high());
        let sig_low = sig.normalize_s().unwrap_or(sig);
        let recid = RecoveryId::new(is_y_odd, recid.is_x_reduced());

        debug!("Signed hash with recovery ID: {}", recid.to_byte());
        Ok((sig_low, recid))
    }

    /// Sign a prehash and return the signature as a hex string
    ///
    /// Returns a 130-character hex string: 64 bytes signature (128 chars) + 1 byte recovery ID (2 chars)
    /// The recovery ID is in raw k256 format (0-3). Use `sign_prehash_to_hex_with_format` for EVM format.
    pub fn sign_prehash_to_hex(&self, hash: &[u8; 32]) -> Result<String, SigningError> {
        self.sign_prehash_to_hex_with_format(hash, SignatureVFormat::Raw)
    }

    /// Sign a prehash and return the signature as a hex string with configurable v format
    ///
    /// Returns a 130-character hex string: 64 bytes signature (128 chars) + 1 byte recovery ID (2 chars)
    ///
    /// The recovery ID (v value) format depends on the `v_format` parameter:
    /// - `SignatureVFormat::Raw`: Raw k256 format (0-3)
    /// - `SignatureVFormat::Evm`: EVM-compatible format (27-28), as expected by OpenZeppelin ECDSA.recover
    pub fn sign_prehash_to_hex_with_format(
        &self,
        hash: &[u8; 32],
        v_format: SignatureVFormat,
    ) -> Result<String, SigningError> {
        let (sig, recid) = self.sign_prehash(hash)?;
        let sig_bytes = sig.to_bytes();
        let recid_byte = v_format.convert_v(recid.to_byte());

        // Combine signature (64 bytes) + recovery ID (1 byte)
        let mut result = Vec::with_capacity(65);
        result.extend_from_slice(&sig_bytes);
        result.push(recid_byte);

        Ok(hex::encode(result))
    }
}

impl TryFrom<&[u8]> for Signer {
    type Error = SigningError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_bytes() {
        let valid_bytes = [1u8; 32];
        assert!(Signer::from_bytes(&valid_bytes).is_ok());
    }

    #[test]
    fn test_keccak256() {
        // Test vector from https://emn178.github.io/online-tools/keccak_256.html
        let hash = Signer::keccak256(b"hello");
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_sign_prehash() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let (sig, recid) = signer.sign_prehash(&hash).unwrap();

        assert!(!sig.to_bytes().iter().all(|&x| x == 0));
        assert!(recid.to_byte() < 4);
    }

    #[test]
    fn test_sign_prehash_to_hex() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let hex_sig = signer.sign_prehash_to_hex(&hash).unwrap();

        // Should be 130 hex characters (65 bytes * 2)
        assert_eq!(hex_sig.len(), 130);

        // Should be valid hex
        assert!(hex::decode(&hex_sig).is_ok());

        // Decode and verify structure
        let decoded = hex::decode(&hex_sig).unwrap();
        assert_eq!(decoded.len(), 65);

        // First 64 bytes are signature (r, s)
        let signature_bytes = &decoded[0..64];
        assert!(!signature_bytes.iter().all(|&x| x == 0));

        // Last byte is recovery ID (should be 0-3)
        let recid = decoded[64];
        assert!(recid < 4);
    }

    #[test]
    fn test_sign_prehash_to_hex_deterministic() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let hex_sig1 = signer.sign_prehash_to_hex(&hash).unwrap();
        let hex_sig2 = signer.sign_prehash_to_hex(&hash).unwrap();

        // Same input should produce same signature
        assert_eq!(hex_sig1, hex_sig2);
    }

    #[test]
    fn test_sign_prehash_to_hex_different_hashes() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash1 = Signer::keccak256(b"test1");
        let hash2 = Signer::keccak256(b"test2");

        let hex_sig1 = signer.sign_prehash_to_hex(&hash1).unwrap();
        let hex_sig2 = signer.sign_prehash_to_hex(&hash2).unwrap();

        // Different hashes should produce different signatures
        assert_ne!(hex_sig1, hex_sig2);
    }

    #[test]
    fn test_from_file_binary() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a binary key file (32 bytes)
        let mut file = NamedTempFile::new().unwrap();
        let key_bytes = [1u8; 32];
        file.write_all(&key_bytes).unwrap();
        file.flush().unwrap();

        // Load from binary file
        let signer = Signer::from_file(file.path()).unwrap();

        // Verify it works
        let hash = Signer::keccak256(b"test");
        let (sig, _) = signer.sign_prehash(&hash).unwrap();
        assert!(!sig.to_bytes().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_from_file_wrong_size() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a file with wrong size (16 bytes instead of 32)
        let mut file = NamedTempFile::new().unwrap();
        let key_bytes = [1u8; 16];
        file.write_all(&key_bytes).unwrap();
        file.flush().unwrap();

        // Should fail
        assert!(Signer::from_file(file.path()).is_err());
    }

    #[test]
    fn test_signature_v_format_convert_v() {
        // Raw format keeps values as-is
        assert_eq!(SignatureVFormat::Raw.convert_v(0), 0);
        assert_eq!(SignatureVFormat::Raw.convert_v(1), 1);
        assert_eq!(SignatureVFormat::Raw.convert_v(2), 2);
        assert_eq!(SignatureVFormat::Raw.convert_v(3), 3);

        // EVM format adds 27
        assert_eq!(SignatureVFormat::Evm.convert_v(0), 27);
        assert_eq!(SignatureVFormat::Evm.convert_v(1), 28);
        assert_eq!(SignatureVFormat::Evm.convert_v(2), 29);
        assert_eq!(SignatureVFormat::Evm.convert_v(3), 30);
    }

    #[test]
    fn test_signature_v_format_default_is_raw() {
        assert_eq!(SignatureVFormat::default(), SignatureVFormat::Raw);
    }

    #[test]
    fn test_signature_v_format_from_str() {
        // "evm" (case-insensitive) -> Evm
        assert_eq!(
            "evm".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Evm
        );
        assert_eq!(
            "EVM".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Evm
        );
        assert_eq!(
            "Evm".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Evm
        );

        // "raw" and anything else -> Raw
        assert_eq!(
            "raw".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Raw
        );
        assert_eq!(
            "RAW".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Raw
        );
        assert_eq!(
            "unknown".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Raw
        );
        assert_eq!(
            "".parse::<SignatureVFormat>().unwrap(),
            SignatureVFormat::Raw
        );
    }

    #[test]
    fn test_sign_prehash_to_hex_with_evm_format() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let hex_sig = signer
            .sign_prehash_to_hex_with_format(&hash, SignatureVFormat::Evm)
            .unwrap();

        // Should be 130 hex characters (65 bytes * 2)
        assert_eq!(hex_sig.len(), 130);

        // Decode and verify v is in EVM range (27-30)
        let decoded = hex::decode(&hex_sig).unwrap();
        let v = decoded[64];
        assert!(v >= 27 && v <= 30, "Expected v in 27-30 range, got {}", v);
    }

    #[test]
    fn test_sign_prehash_to_hex_with_raw_format() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let hex_sig = signer
            .sign_prehash_to_hex_with_format(&hash, SignatureVFormat::Raw)
            .unwrap();

        // Should be 130 hex characters (65 bytes * 2)
        assert_eq!(hex_sig.len(), 130);

        // Decode and verify v is in raw range (0-3)
        let decoded = hex::decode(&hex_sig).unwrap();
        let v = decoded[64];
        assert!(v < 4, "Expected v in 0-3 range, got {}", v);
    }

    #[test]
    fn test_evm_and_raw_signatures_only_differ_in_v() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let hash = Signer::keccak256(b"test");
        let raw_sig = signer
            .sign_prehash_to_hex_with_format(&hash, SignatureVFormat::Raw)
            .unwrap();
        let evm_sig = signer
            .sign_prehash_to_hex_with_format(&hash, SignatureVFormat::Evm)
            .unwrap();

        let raw_bytes = hex::decode(&raw_sig).unwrap();
        let evm_bytes = hex::decode(&evm_sig).unwrap();

        // r and s should be identical (first 64 bytes)
        assert_eq!(&raw_bytes[..64], &evm_bytes[..64]);

        // v should differ by 27
        assert_eq!(raw_bytes[64] + 27, evm_bytes[64]);
    }
}
