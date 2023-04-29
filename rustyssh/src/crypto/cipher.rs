use std::collections::HashMap;

use once_cell::sync::Lazy;
use ring::error;

use crate::namelist::Name;

use self::aes_gcm::{AES_GCM_128, AES_GCM_256};

use super::hmac::Hmac;

pub mod aes_gcm;
pub mod none;

pub trait Cipher {
    fn make_cipher(&mut self, key: &[u8], iv: &[u8])
        -> Result<Box<dyn Cipher>, error::Unspecified>;

    fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), error::Unspecified>;

    fn encrypt_in_place(&mut self, plaintext: &mut [u8]) -> Result<(), error::Unspecified>;

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), error::Unspecified>;

    fn decrypt_in_place(&mut self, ciphertext: &mut [u8]) -> Result<(), error::Unspecified>;

    fn aead_crypt(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        direction: Direction,
    ) -> Result<(), error::Unspecified>;

    fn aead_crypt_in_place(
        &mut self,
        input: &mut [u8],
        direction: Direction,
    ) -> Result<(), error::Unspecified>;

    fn aead_getlength(&mut self, input: &[u8]) -> Result<u32, error::Unspecified>;

    fn aead_mac(&self) -> &Hmac;

    fn keysize(&self) -> usize;
    fn blocksize(&self) -> usize;

    fn is_aead(&self) -> bool;
}

pub const AES_128_GCM: Name = Name("aes128-gcm@openssh.com");
pub const AES_256_GCM: Name = Name("aes256-gcm@openssh.com");

pub static CIPHERS: Lazy<HashMap<&'static Name, &(dyn Cipher + Send + Sync)>> = Lazy::new(|| {
    let mut h: HashMap<&'static Name, &(dyn Cipher + Send + Sync)> = HashMap::new();
    h.insert(&AES_256_GCM, &AES_GCM_256);
    h.insert(&AES_128_GCM, &AES_GCM_128);
    h
});

pub enum Direction {
    Encrypt,
    Decrypt,
}
