use ring::{
    aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, NONCE_LEN},
    error,
};

use super::{Crypt, Direction};

const GCM_IVFIX_LEN: usize = 4;
const GCM_IVCTR_LEN: usize = 8;

pub struct AesGcm {
    mode: &'static Algorithm,
    key: Option<LessSafeKey>,
    iv: Option<[u8; NONCE_LEN]>,
}

pub fn new_aes_gcm_256() -> Box<dyn Crypt> {
    Box::new(AesGcm {
        mode: &AES_256_GCM,
        key: None,
        iv: None,
    })
}

pub fn new_aes_gcm_128() -> Box<dyn Crypt> {
    Box::new(AesGcm {
        mode: &AES_128_GCM,
        key: None,
        iv: None,
    })
}

impl AesGcm {
    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), error::Unspecified> {
        let unbound_key = UnboundKey::new(self.mode, key);
        if unbound_key.is_err() {
            return Err(unbound_key.err().unwrap());
        }
        self.key = Some(LessSafeKey::new(unbound_key.unwrap()));
        let mut new_iv = [0u8; NONCE_LEN];
        new_iv.copy_from_slice(&iv[..NONCE_LEN]);
        self.iv = Some(new_iv);
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        if self.key.is_none() {
            return Err(error::Unspecified);
        }

        let total_len = plaintext.len() + self.key.as_ref().unwrap().algorithm().tag_len();

        if plaintext.len() < 4 || ciphertext.len() != total_len {
            return Err(error::Unspecified);
        }

        let nonce = self.get_nonce();

        if nonce.is_err() {
            return Err(error::Unspecified);
        }
        let nonce = nonce.unwrap();

        let aad = self.get_aad(plaintext);

        // copy plaintext
        let mut temp_in = Vec::with_capacity(total_len - 4);
        temp_in.extend_from_slice(&plaintext[4..]);

        let res = self
            .key
            .as_ref()
            .unwrap()
            .seal_in_place_append_tag(nonce, aad, &mut temp_in);

        if res.is_err() {
            return Err(error::Unspecified);
        }

        // copy packet-length
        ciphertext[..4].copy_from_slice(&plaintext[..4]);

        // copy cipher text
        ciphertext[4..temp_in.len() + 4].copy_from_slice(&temp_in);

        if let Err(_) = self.increment_iv_counter() {
            return Err(error::Unspecified);
        }

        Ok(())
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        if self.key.is_none() {
            return Err(error::Unspecified);
        }

        let total_len = ciphertext.len() - self.key.as_ref().unwrap().algorithm().tag_len();

        if ciphertext.len() < 4 || plaintext.len() != total_len {
            return Err(error::Unspecified);
        }

        let nonce = self.get_nonce();

        if nonce.is_err() {
            return Err(error::Unspecified);
        }
        let nonce = nonce.unwrap();

        let aad = self.get_aad(ciphertext);

        // copy plaintext
        let mut temp_in = Vec::with_capacity(ciphertext.len() - 4);
        temp_in.extend_from_slice(&ciphertext[4..]);

        let decrypted = self
            .key
            .as_ref()
            .unwrap()
            .open_in_place(nonce, aad, &mut temp_in);

        if decrypted.is_err() {
            return Err(error::Unspecified);
        }

        let decrypted = decrypted.unwrap();

        // copy packet-length
        plaintext[..4].copy_from_slice(&ciphertext[..4]);

        // copy plaintext
        plaintext[4..decrypted.len() + 4].copy_from_slice(&decrypted);

        if let Err(_) = self.increment_iv_counter() {
            return Err(error::Unspecified);
        }

        Ok(())
    }

    pub fn get_nonce(&mut self) -> Result<Nonce, error::Unspecified> {
        if self.iv.is_none() {
            return Err(error::Unspecified);
        }

        // get nonce
        let iv = self.iv.unwrap().clone();
        let nonce = Nonce::assume_unique_for_key(iv);

        Ok(nonce)
    }

    pub fn get_aad(&mut self, plaintext: &[u8]) -> Aad<[u8; 4]> {
        // get aad from plain text which is the packet-length
        let mut aad = [0u8; 4];
        aad.copy_from_slice(&plaintext[..4]);
        Aad::from(aad)
    }

    pub fn increment_iv_counter(&mut self) -> Result<(), error::Unspecified> {
        if self.iv.is_none() {
            return Err(error::Unspecified);
        }

        // get counter
        let mut iv_counter = [0u8; GCM_IVCTR_LEN];
        iv_counter.copy_from_slice(&self.iv.as_ref().unwrap()[GCM_IVFIX_LEN..]);
        let mut counter = u64::from_le_bytes(iv_counter);

        // increment it by 1
        counter += 1;

        // set the counter back to iv
        self.iv.as_mut().unwrap()[GCM_IVFIX_LEN..].copy_from_slice(&counter.to_le_bytes());

        Ok(())
    }
}

impl Crypt for AesGcm {
    fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), error::Unspecified> {
        self.init(key, iv)
    }

    fn encrypt(
        &mut self,
        _plaintext: &[u8],
        _ciphertext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        Err(error::Unspecified)
    }

    fn decrypt(
        &mut self,
        _ciphertext: &[u8],
        _plaintext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        Err(error::Unspecified)
    }

    fn aead_crypt(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        direction: Direction,
    ) -> Result<(), error::Unspecified> {
        match direction {
            Direction::Encrypt => self.encrypt(input, output),
            Direction::Decrypt => self.decrypt(input, output),
        }
    }

    fn is_aead(&mut self) -> bool {
        return true;
    }
}
