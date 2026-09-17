//! EVM address derivation from signing keys

use sha3::{Digest, Keccak256};

use super::Signer;

/// EVM address as a hex string (e.g., "0x1234...abcd")
pub type EvmAddress = String;

/// Derive EVM address from a Signer
impl From<&Signer> for EvmAddress {
    fn from(signer: &Signer) -> Self {
        // Get the uncompressed public key bytes (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
        let public_key_bytes = signer
            .signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();

        // Skip the 0x04 prefix byte and hash the remaining 64 bytes
        let key_hash: [u8; 32] = Keccak256::digest(&public_key_bytes[1..]).into();

        // Take last 20 bytes of the hash as the address
        let address_bytes = &key_hash[12..];
        format!("0x{}", hex::encode(address_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_address_from_signer() {
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let address = EvmAddress::from(&signer);

        // Verify address format
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // "0x" + 40 hex chars

        // Same key should produce same address
        let address2 = EvmAddress::from(&signer);
        assert_eq!(address, address2);
    }

    #[test]
    fn test_different_keys_produce_different_addresses() {
        let signer1 = Signer::from_bytes(&[1u8; 32]).unwrap();
        let signer2 = Signer::from_bytes(&[2u8; 32]).unwrap();

        let address1 = EvmAddress::from(&signer1);
        let address2 = EvmAddress::from(&signer2);

        assert_ne!(address1, address2);
    }

    #[test]
    fn test_known_address() {
        // Test vector from https://github.com/ethereum/tests/blob/develop/BasicTests/keyaddrtest.json
        let private_key =
            hex::decode("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4")
                .unwrap();
        let expected_address = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";

        let signer = Signer::from_bytes(&private_key).unwrap();
        let address = EvmAddress::from(&signer);

        assert_eq!(address.to_lowercase(), expected_address);
    }

    #[test]
    fn test_another_known_address() {
        // Additional test vector
        let private_key =
            hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let expected_address = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";

        let signer = Signer::from_bytes(&private_key).unwrap();
        let address = EvmAddress::from(&signer);

        assert_eq!(address.to_lowercase(), expected_address);
    }
}
