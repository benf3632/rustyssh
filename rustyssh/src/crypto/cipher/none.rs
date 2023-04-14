use super::Crypt;

pub struct NoneCipher {}

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

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        plaintext.copy_from_slice(ciphertext);
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

    fn is_aead(&mut self) -> bool {
        false
    }
}
