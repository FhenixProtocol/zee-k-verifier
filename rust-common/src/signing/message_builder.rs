//! Generic message builder for signing
//!
//! Provides a fluent API for building messages to be signed, similar to
//! Ethereum's `abi.encodePacked()`. Fields are concatenated in the order
//! they are added.

use super::Signer;

/// Trait for types that can be encoded into a signing message.
///
/// - Integers: big-endian bytes
/// - Strings: UTF-8 bytes (no length prefix)
/// - Byte slices/arrays: raw bytes (no length prefix)
pub trait SigningEncode {
    fn encode_to(&self, buffer: &mut Vec<u8>);
}

// Implement for byte slices
impl SigningEncode for &[u8] {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self);
    }
}

impl SigningEncode for Vec<u8> {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self);
    }
}

// Implement for string types
impl SigningEncode for &str {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes());
    }
}

impl SigningEncode for String {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes());
    }
}

// Implement for integer types (big-endian)
impl SigningEncode for u8 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self);
    }
}

impl SigningEncode for u16 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_be_bytes());
    }
}

impl SigningEncode for u32 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_be_bytes());
    }
}

impl SigningEncode for u64 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_be_bytes());
    }
}

impl SigningEncode for i32 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_be_bytes());
    }
}

impl SigningEncode for i64 {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_be_bytes());
    }
}

// Implement for fixed-size byte arrays
impl<const N: usize> SigningEncode for [u8; N] {
    fn encode_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self);
    }
}

/// A builder for constructing messages to be signed.
///
/// Fields are concatenated in the order they are added, producing a byte
/// array that can be hashed and signed.
///
/// # Example
///
/// ```
/// use rust_common::signing::SigningMessageBuilder;
///
/// let message = SigningMessageBuilder::new()
///     .add(&[1u8, 2, 3, 4][..])  // bytes
///     .add(1i32)                  // i32 as big-endian
///     .add(421614u64)             // u64 as big-endian
///     .add("0xabc123")            // string as UTF-8 bytes
///     .add("req-123")
///     .build();
///
/// // Hash the message for signing
/// use rust_common::signing::Signer;
/// let hash = Signer::keccak256(&message);
/// ```
#[derive(Debug, Clone, Default)]
pub struct SigningMessageBuilder {
    buffer: Vec<u8>,
}

impl SigningMessageBuilder {
    /// Create a new empty message builder
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Create a new message builder with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Add a value to the message
    /// The value is encoded according to its type
    #[allow(clippy::should_implement_trait)]
    pub fn add<T: SigningEncode>(mut self, value: T) -> Self {
        value.encode_to(&mut self.buffer);
        self
    }

    /// Build the final message bytes
    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    /// Build and compute the Keccak256 hash
    pub fn build_hash(self) -> [u8; 32] {
        Signer::keccak256(&self.buffer)
    }

    /// Get current length of the buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_builder() {
        let msg = SigningMessageBuilder::new().build();
        assert!(msg.is_empty());
    }

    #[test]
    fn test_add_bytes() {
        let msg = SigningMessageBuilder::new()
            .add(&[1u8, 2, 3, 4][..])
            .build();
        assert_eq!(msg, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_add_u64() {
        let msg = SigningMessageBuilder::new()
            .add(0x0102030405060708u64)
            .build();
        assert_eq!(msg, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_add_i32() {
        let msg = SigningMessageBuilder::new().add(1i32).build();
        assert_eq!(msg, vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_add_str() {
        let msg = SigningMessageBuilder::new().add("hello").build();
        assert_eq!(msg, b"hello".to_vec());
    }

    #[test]
    fn test_add_string() {
        let msg = SigningMessageBuilder::new()
            .add(String::from("hello"))
            .build();
        assert_eq!(msg, b"hello".to_vec());
    }

    #[test]
    fn test_add_vec() {
        let msg = SigningMessageBuilder::new().add(vec![1u8, 2, 3]).build();
        assert_eq!(msg, vec![1, 2, 3]);
    }

    #[test]
    fn test_add_fixed_array() {
        let msg = SigningMessageBuilder::new().add([1u8, 2, 3, 4]).build();
        assert_eq!(msg, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_chained_additions() {
        let msg = SigningMessageBuilder::new()
            .add(&[1u8, 2, 3, 4][..])
            .add(1i32)
            .add(421614u64)
            .add("0xabc123")
            .add("req-123")
            .build();

        // Verify structure
        assert_eq!(&msg[0..4], &[1, 2, 3, 4]); // bytes
        assert_eq!(&msg[4..8], &[0, 0, 0, 1]); // i32
        assert_eq!(&msg[8..16], &421614u64.to_be_bytes()); // u64
                                                           // Rest is string data
        assert!(msg.len() > 16);
    }

    #[test]
    fn test_build_hash() {
        let hash = SigningMessageBuilder::new().add("hello").build_hash();

        // Should match keccak256("hello")
        let expected = Signer::keccak256(b"hello");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_with_capacity() {
        let builder = SigningMessageBuilder::with_capacity(100);
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn test_different_messages_different_hashes() {
        let hash1 = SigningMessageBuilder::new()
            .add(&[1u8, 2, 3][..])
            .build_hash();

        let hash2 = SigningMessageBuilder::new()
            .add(&[1u8, 2, 4][..])
            .build_hash();

        assert_ne!(hash1, hash2);
    }
}
