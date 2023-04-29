use ring::{
    digest::SHA256_OUTPUT_LEN,
    hmac::{self, Tag},
};

use crate::utils::error::SSHError;

pub struct Hmac {
    pub mode: Option<&'static ring::hmac::Algorithm>,
    pub hashsize: usize,
    pub keysize: usize,
}

pub static HMAC_SHA256: Hmac = Hmac {
    mode: Some(&ring::hmac::HMAC_SHA256),
    hashsize: SHA256_OUTPUT_LEN,
    keysize: SHA256_OUTPUT_LEN,
};

pub static HMAC_NONE: Hmac = Hmac {
    mode: None,
    hashsize: 0,
    keysize: 0,
};

pub fn compute_hmac(mode: &ring::hmac::Algorithm, key_value: &[u8], msg: &[u8]) -> Tag {
    let key = hmac::Key::new(*mode, key_value);

    hmac::sign(&key, msg)
}

pub fn verify_hmac(
    mode: &ring::hmac::Algorithm,
    key_value: &[u8],
    msg: &[u8],
    tag: &[u8],
) -> Result<(), SSHError> {
    let key = hmac::Key::new(*mode, key_value);

    hmac::verify(&key, msg, tag).map_err(|_| SSHError::Failure)
}
