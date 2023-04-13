use crate::crypto::kex::dh_groups::DH_P_14;

pub struct AlgoType {
    pub name: &'static str,
    pub usable: bool,
    pub kex: Option<&'static Kex>,
    // cipher_mode: CipherMode,
}

pub enum KexMode {
    NormalDH(&'static [u8]),
    // ECDH(),
    // CURVE25519,
}

pub struct Kex {
    mode: KexMode,
    digest: &'static ring::digest::Algorithm,
}

pub static SSH_NOCOMPRESS: [AlgoType; 1] = [AlgoType {
    name: "none",
    usable: true,
    kex: None,
}];

const KEX_DH_GROUP14_MODE: KexMode = KexMode::NormalDH(&DH_P_14);
static KEX_DH_GROUP14_SHA256: Kex = Kex {
    mode: KEX_DH_GROUP14_MODE,
    digest: &ring::digest::SHA256,
};

static KEX_DH_GROUP14_SHA1: Kex = Kex {
    mode: KEX_DH_GROUP14_MODE,
    digest: &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
};

pub static SSHKEX: [AlgoType; 2] = [
    // TODO: don't forget to add required algos
    AlgoType {
        name: "diffie-hellman-group14-sha256",
        usable: true,
        kex: Some(&KEX_DH_GROUP14_SHA256),
    },
    AlgoType {
        name: "diffie-hellman-group14-sha1",
        usable: true,
        kex: Some(&KEX_DH_GROUP14_SHA1),
    },
];
