use crate::crypto::cipher::{CipherMode, AES_256_GCM};
use crate::crypto::kex::dh_groups::DH_P_14;
use crate::signkey::SignatureType;
use crate::sshbuffer::SSHBuffer;

pub struct AlgoType<'a> {
    pub name: &'static str,
    pub usable: bool,
    pub kex: Option<&'a Kex>,
    // cipher_mode: CipherMode,
    pub sig_type: Option<SignatureType>,
    pub hash: Option<&'a Hash>,
    pub cipher: Option<&'static CipherMode>,
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

pub const SSH_NOCOMPRESS: [AlgoType; 1] = [AlgoType {
    name: "none",
    usable: true,
    kex: None,
    sig_type: None,
    hash: None,
    cipher: None,
}];

const KEX_DH_GROUP14_MODE: KexMode = KexMode::NormalDH(&DH_P_14);
const KEX_DH_GROUP14_SHA256: Kex = Kex {
    mode: KEX_DH_GROUP14_MODE,
    digest: Digest::SHA256,
};

const KEX_DH_GROUP14_SHA1: Kex = Kex {
    mode: KEX_DH_GROUP14_MODE,
    digest: Digest::SHA1,
};

pub const SSHKEX: [AlgoType; 2] = [
    // TODO: don't forget to add required algos
    AlgoType {
        name: "diffie-hellman-group14-sha256",
        usable: true,
        kex: Some(&KEX_DH_GROUP14_SHA256),
        sig_type: None,
        hash: None,
        cipher: None,
    },
    AlgoType {
        name: "diffie-hellman-group14-sha1",
        usable: true,
        kex: Some(&KEX_DH_GROUP14_SHA1),
        sig_type: None,
        hash: None,
        cipher: None,
    },
];

pub const SIGALGS: [AlgoType; 1] = [AlgoType {
    name: "ssh-rsa",
    usable: true,
    kex: None,
    sig_type: Some(SignatureType::RSA_SHA1),
    hash: None,
    cipher: None,
}];

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

pub const SSHHASHES: [AlgoType; 1] = [AlgoType {
    name: "hmac-sha2-256",
    usable: true,
    sig_type: None,
    kex: None,
    hash: Some(&SHA2_256),
    cipher: None,
}];

pub const SSHCIPHERS: [AlgoType; 1] = [AlgoType {
    name: "aes256-gcm@openssh.com",
    usable: true,
    sig_type: None,
    kex: None,
    hash: None,
    cipher: Some(&AES_256_GCM),
}];

impl SSHBuffer {
    pub fn put_algolist(&mut self, algolist: &[AlgoType]) {
        let mut total_len = 0;
        let mut donefirst = false;
        let start_pos = self.pos();
        // placeholder for the len of the name-list after insert
        self.put_int(total_len);
        for algo in algolist {
            if algo.usable {
                if donefirst {
                    self.put_byte(',' as u8);
                }
                donefirst = true;
                self.put_bytes(algo.name.as_bytes());
            }
        }
        // fill out the length
        total_len = self.pos() as u32 - start_pos as u32 - 4;
        self.set_pos(start_pos);
        self.put_int(total_len);
        // set position after the name-list
        self.incr_write_pos(total_len as usize);
    }
}
