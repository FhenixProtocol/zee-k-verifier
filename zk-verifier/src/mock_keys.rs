use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use rust_common::log::info;
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, CompactPublicKey, ServerKey};

use crate::config::KeyConfig;
use crate::verifier::Verifier;

pub fn get_keys(
    _key_config: &KeyConfig,
) -> (CompactPkeCrs, CompactPublicKey, ServerKey, SigningKey) {
    info!("Creating mock FHE keys...");
    let config = tfhe::ConfigBuilder::with_custom_parameters(Verifier::PARAMS)
        .use_dedicated_compact_public_key_parameters((
            Verifier::CPK_PARAMS,
            Verifier::CASTING_PARAMS,
        ))
        .build();

    let crs = CompactPkeCrs::from_config(config, 1024).unwrap();
    let client_key = ClientKey::generate(config);
    let pk = CompactPublicKey::try_new(&client_key).unwrap();
    let server_key = ServerKey::new(&client_key);

    // Create a mock signing key
    let signing_key = SigningKey::random(&mut OsRng);

    (crs, pk, server_key, signing_key)
}
