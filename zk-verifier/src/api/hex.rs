use ::hex as hex_crate;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(dead_code)]
pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex_crate::encode(bytes));
    hex_string.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex_crate::decode(string).map_err(|err| Error::custom(err.to_string())))
}
