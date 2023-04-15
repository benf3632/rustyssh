use crate::algo::{Digest, Hash};

use super::Crypt;

pub struct NoneCipher {}

pub const NONE_CIPHER_HASH: Hash = Hash {
    digest: Digest::None,
    hashsize: 0,
    keysize: 16,
};

pub fn new_none_cipher() -> Box<dyn Crypt> {
    Box::new(NoneCipher {})
}

impl Crypt for NoneCipher {
    fn init(&mut self, _key: &[u8], _iv: &[u8]) -> Result<(), ring::error::Unspecified> {
        Ok(())
    }

    fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        ciphertext.copy_from_slice(plaintext);
        Ok(())
    }

    fn encrypt_in_place(&mut self, _plaintext: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        plaintext.copy_from_slice(ciphertext);
        Ok(())
    }

    fn decrypt_in_place(&mut self, _ciphertext: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        Ok(())
    }

    fn aead_crypt(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
        _direction: super::Direction,
    ) -> Result<(), ring::error::Unspecified> {
        Err(ring::error::Unspecified)
    }

    fn aead_crypt_in_place(
        &mut self,
        _input: &mut [u8],
        _direction: super::Direction,
    ) -> Result<(), ring::error::Unspecified> {
        Err(ring::error::Unspecified)
    }

    fn aead_getlength(&mut self, _input: &[u8]) -> Result<u32, ring::error::Unspecified> {
        Err(ring::error::Unspecified)
    }

    fn aead_mac(&self) -> Hash {
        NONE_CIPHER_HASH
    }

    fn is_aead(&self) -> bool {
        false
    }
}
