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

pub static ssh_nocompress: [AlgoType; 1] = [AlgoType {
    name: "none",
    usable: true,
    kex: None,
}];

const kex_dh_group14_mode: KexMode = KexMode::NormalDH(&DH_P_14);
static kex_dh_group14_sha256: Kex = Kex {
    mode: kex_dh_group14_mode,
    digest: &ring::digest::SHA256,
};

static kex_dh_group14_sha1: Kex = Kex {
    mode: kex_dh_group14_mode,
    digest: &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
};

pub static sshkex: [AlgoType; 2] = [
    AlgoType {
        name: "diffie-hellman-group14-sha256",
        usable: true,
        kex: Some(&kex_dh_group14_sha256),
    },
    AlgoType {
        name: "diffie-hellman-group14-sha1",
        usable: true,
        kex: Some(&kex_dh_group14_sha1),
    },
];
