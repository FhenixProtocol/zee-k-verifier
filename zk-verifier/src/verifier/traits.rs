use tfhe::prelude::CiphertextList;
use tfhe::{CompactCiphertextListExpander, FheTypes};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub trait SerializeFromExpander {
    fn serialize(expander: &CompactCiphertextListExpander, index: usize)
        -> Result<Option<Vec<u8>>>;
}

macro_rules! impl_serialize_from_expander {
    ($($t:ty),*) => {
        $(
            impl SerializeFromExpander for $t {
                fn serialize(
                    expander: &CompactCiphertextListExpander,
                    index: usize,
                ) -> Result<Option<Vec<u8>>> {
                    let ct = match expander.get::<$t>(index)? {
                        Some(ct) => ct,
                        None => return Ok(None),
                    };
                    let compressed = ct.compress();
                    let buf = rust_common::safe_serde::serialize(&compressed)
                        .map_err(|e| Box::<dyn std::error::Error>::from(e))?;
                    Ok(Some(buf))
                }
            }
        )*
    };
}

impl_serialize_from_expander!(
    tfhe::FheBool,
    tfhe::FheUint4,
    tfhe::FheUint8,
    tfhe::FheUint16,
    tfhe::FheUint32,
    tfhe::FheUint64,
    tfhe::FheUint128,
    tfhe::FheUint160,
    tfhe::FheUint256,
    tfhe::FheUint512,
    tfhe::FheUint1024,
    tfhe::FheUint2048,
    tfhe::FheUint2,
    tfhe::FheUint6,
    tfhe::FheUint10,
    tfhe::FheUint12,
    tfhe::FheUint14,
    tfhe::FheInt2,
    tfhe::FheInt4,
    tfhe::FheInt6,
    tfhe::FheInt8,
    tfhe::FheInt10,
    tfhe::FheInt12,
    tfhe::FheInt14,
    tfhe::FheInt16,
    tfhe::FheInt32,
    tfhe::FheInt64,
    tfhe::FheInt128,
    tfhe::FheInt160,
    tfhe::FheInt256
);

pub trait SerializeIndex {
    fn serialize_index(&self, index: usize) -> Result<Option<(FheTypes, Vec<u8>)>>;
}

impl SerializeIndex for CompactCiphertextListExpander {
    fn serialize_index(&self, index: usize) -> Result<Option<(FheTypes, Vec<u8>)>> {
        let ct_type = match self.get_kind_of(index) {
            Some(ct_type) => ct_type,
            None => return Ok(None),
        };

        match ct_type {
            tfhe::FheTypes::Bool => tfhe::FheBool::serialize(self, index),
            tfhe::FheTypes::Uint4 => tfhe::FheUint4::serialize(self, index),
            tfhe::FheTypes::Uint8 => tfhe::FheUint8::serialize(self, index),
            tfhe::FheTypes::Uint16 => tfhe::FheUint16::serialize(self, index),
            tfhe::FheTypes::Uint32 => tfhe::FheUint32::serialize(self, index),
            tfhe::FheTypes::Uint64 => tfhe::FheUint64::serialize(self, index),
            tfhe::FheTypes::Uint128 => tfhe::FheUint128::serialize(self, index),
            tfhe::FheTypes::Uint160 => tfhe::FheUint160::serialize(self, index),
            tfhe::FheTypes::Uint256 => tfhe::FheUint256::serialize(self, index),
            tfhe::FheTypes::Uint512 => tfhe::FheUint512::serialize(self, index),
            tfhe::FheTypes::Uint1024 => tfhe::FheUint1024::serialize(self, index),
            tfhe::FheTypes::Uint2048 => tfhe::FheUint2048::serialize(self, index),
            tfhe::FheTypes::Uint2 => tfhe::FheUint2::serialize(self, index),
            tfhe::FheTypes::Uint6 => tfhe::FheUint6::serialize(self, index),
            tfhe::FheTypes::Uint10 => tfhe::FheUint10::serialize(self, index),
            tfhe::FheTypes::Uint12 => tfhe::FheUint12::serialize(self, index),
            tfhe::FheTypes::Uint14 => tfhe::FheUint14::serialize(self, index),
            tfhe::FheTypes::Int2 => tfhe::FheInt2::serialize(self, index),
            tfhe::FheTypes::Int4 => tfhe::FheInt4::serialize(self, index),
            tfhe::FheTypes::Int6 => tfhe::FheInt6::serialize(self, index),
            tfhe::FheTypes::Int8 => tfhe::FheInt8::serialize(self, index),
            tfhe::FheTypes::Int10 => tfhe::FheInt10::serialize(self, index),
            tfhe::FheTypes::Int12 => tfhe::FheInt12::serialize(self, index),
            tfhe::FheTypes::Int14 => tfhe::FheInt14::serialize(self, index),
            tfhe::FheTypes::Int16 => tfhe::FheInt16::serialize(self, index),
            tfhe::FheTypes::Int32 => tfhe::FheInt32::serialize(self, index),
            tfhe::FheTypes::Int64 => tfhe::FheInt64::serialize(self, index),
            tfhe::FheTypes::Int128 => tfhe::FheInt128::serialize(self, index),
            tfhe::FheTypes::Int160 => tfhe::FheInt160::serialize(self, index),
            tfhe::FheTypes::Int256 => tfhe::FheInt256::serialize(self, index),
            _ => return Err(format!("Unsupported ciphertext type: {:?}", ct_type).into()),
        }
        .map(|ct| ct.map(|ct| (ct_type, ct)))
    }
}
