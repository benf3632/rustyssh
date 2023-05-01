use crate::crypto::cipher;
use crate::crypto::signature::RSA_SHA2_256;
use crate::sshbuffer::SSHBuffer;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(pub &'static str);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }

    fn ne(&self, other: &str) -> bool {
        self.0 != other
    }
}

pub enum KexMode {
    NormalDH(&'static [u8]),
    // ECDH(),
    // CURVE25519,
}

pub enum Digest {
    None,
    SHA256,
    SHA1,
}

pub struct Kex {
    pub mode: KexMode,
    pub digest: Digest,
}

pub const CIPHER_ORDER: &[Name] = &[cipher::AES_256_GCM, cipher::AES_128_GCM];
pub const KEX_ORDER: &[Name] = &[KEX_DH_GROUP14_SHA256, KEX_DH_GROUP14_SHA1];
pub const COMPRESSION_ORDER: &[Name] = &[NONE];
pub const SIGNATURE_ORDER: &[Name] = &[RSA_SHA2_256];
pub const HMAC_ORDER: &[Name] = &[HMAC_256];

pub const KEX_DH_GROUP14_SHA256: Name = Name("diffie-hellman-group14-sha256");
pub const KEX_DH_GROUP14_SHA1: Name = Name("diffie-hellman-group14-sha1");

pub const HMAC_256: Name = Name("hmac-sha2-256");

pub const NONE: Name = Name("none");

pub struct Hash {
    pub digest: Digest,
    pub keysize: u64,
    pub hashsize: u8,
}

const SHA2_256: Hash = Hash {
    digest: Digest::SHA256,
    keysize: 32,
    hashsize: 32,
};

impl SSHBuffer {
    pub fn put_namelist(&mut self, namelist: &[Name]) {
        let mut total_len = 0;
        let mut donefirst = false;
        let start_pos = self.pos();
        // placeholder for the len of the name-list after insert
        self.put_int(total_len);
        for name in namelist {
            if donefirst {
                self.put_byte(',' as u8);
            }
            donefirst = true;
            self.put_bytes(name.as_ref().as_bytes());
        }
        // fill out the length
        total_len = self.pos() as u32 - start_pos as u32 - 4;
        self.set_pos(start_pos);
        self.put_int(total_len);
        // set position after the name-list
        self.incr_write_pos(total_len as usize);
    }
}
