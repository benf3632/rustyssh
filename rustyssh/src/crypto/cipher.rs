use ring::error;

use crate::algo::Hash;

use self::{
    aes_gcm::{new_aes_gcm_128, new_aes_gcm_256},
    none::new_none_cipher,
};

pub mod aes_gcm;
pub mod none;

pub struct CipherMode {
    pub keysize: u64,
    pub blocksize: u8,
    pub cipher_init: &'static dyn Fn() -> Box<dyn Crypt>,
}

pub struct Cipher {
    pub keysize: u64,
    pub blocksize: u8,
    pub crypt_mode: Box<dyn Crypt>,
}

pub const AES_256_GCM: CipherMode = CipherMode {
    keysize: 32,
    blocksize: 16,
    cipher_init: &new_aes_gcm_256,
};

pub const AES_128_GCM: CipherMode = CipherMode {
    keysize: 16,
    blocksize: 16,
    cipher_init: &new_aes_gcm_128,
};

pub const NONE_CIPHER: CipherMode = CipherMode {
    keysize: 16,
    blocksize: 8,
    cipher_init: &new_none_cipher,
};

pub enum Direction {
    Encrypt,
    Decrypt,
}

pub trait Crypt {
    fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), error::Unspecified>;

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

    fn aead_mac(&self) -> Hash;

    fn is_aead(&self) -> bool;
}
