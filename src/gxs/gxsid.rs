use log::trace;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use retroshare_compat::tlv::tlv_keys::TlvPublicRSAKey;

pub fn verify_signature(
    key: &TlvPublicRSAKey,
    data_signed: &[u8],
    signature: &[u8],
) -> Result<bool, openssl::error::ErrorStack> {
    trace!("verify key {}", hex::encode(key.key_data.as_slice()));
    trace!("verify key flags {:0x}", key.key_flags);
    trace!("verify data {}", hex::encode(data_signed));

    assert!((key.key_flags & 0x02) == 0);

    // get key
    let rsa = Rsa::public_key_from_der_pkcs1(key.key_data.as_slice())?;
    let pkey = PKey::from_rsa(rsa)?;

    // build verifier
    let mut v = Verifier::new(MessageDigest::sha1(), &pkey)?;
    v.update(data_signed)?;
    v.verify(signature)
}

pub fn generate_signature(
    key: &TlvPublicRSAKey,
    data_to_sign: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    trace!("sign key {}", hex::encode(key.key_data.as_slice()));
    trace!("sign key flags {:0x}", key.key_flags);
    trace!("sign data {}", hex::encode(data_to_sign));

    assert!((key.key_flags & 0x02) != 0);

    // get key
    let rsa = Rsa::private_key_from_der(key.key_data.as_slice())?;
    let pkey = PKey::from_rsa(rsa)?;

    // build signer
    let mut s = Signer::new(MessageDigest::sha1(), &pkey)?;
    s.update(data_to_sign)?;
    s.sign_to_vec()
}
