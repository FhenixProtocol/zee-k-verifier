#![allow(dead_code)]

use base64::Engine;
use serde::{Deserialize, Deserializer};

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        base64::engine::general_purpose::STANDARD
            .decode(string)
            .map_err(|err| Error::custom(err.to_string()))
    })
}
