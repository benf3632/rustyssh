use crate::namelist::{Digest, Hash};

use super::Cipher;

pub struct NoneCipher {}

pub const NONE_CIPHER_HASH: Hash = Hash {
    digest: Digest::None,
    hashsize: 0,
    keysize: 16,
};

pub fn new_none_cipher() -> Box<dyn Cipher> {
    Box::new(NoneCipher {})
}

impl Cipher for NoneCipher {
    fn make_cipher(
        &mut self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn Cipher>, ring::error::Unspecified> {
        Ok(Box::new(NoneCipher {}))
    }

    fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        ciphertext.copy_from_slice(&plaintext[..ciphertext.len()]);
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
        plaintext.copy_from_slice(&ciphertext[..plaintext.len()]);
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

    fn blocksize(&self) -> usize {
        8
    }

    fn keysize(&self) -> usize {
        16
    }

    fn is_aead(&self) -> bool {
        false
    }
}
