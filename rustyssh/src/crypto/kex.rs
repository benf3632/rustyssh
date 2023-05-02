use ring::digest::{Algorithm, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::namelist::Name;

use self::dh::{Dh, DH_GROUP14};

pub mod dh;
pub mod dh_groups;

#[derive(Clone)]
pub enum KexType {
    DH(&'static Dh),
    ECDH,
}

#[derive(Clone)]
pub struct KexMode {
    pub kex_type: KexType,
    pub digest: Option<&'static Algorithm>,
}

pub static DH_GROUP14_SHA256_MODE: KexMode = KexMode {
    kex_type: KexType::DH(&DH_GROUP14),
    digest: Some(&SHA256),
};

pub static DH_GROUP14_SHA1_MODE: KexMode = KexMode {
    kex_type: KexType::DH(&DH_GROUP14),
    digest: Some(&SHA1_FOR_LEGACY_USE_ONLY),
};

pub const KEX_DH_GROUP14_SHA256: Name = Name("diffie-hellman-group14-sha256");
pub const KEX_DH_GROUP14_SHA1: Name = Name("diffie-hellman-group14-sha1");

pub static KEXS: Lazy<HashMap<&'static Name, &'static KexMode>> = Lazy::new(|| {
    let mut h: HashMap<&'static Name, &'static KexMode> = HashMap::new();
    h.insert(&KEX_DH_GROUP14_SHA256, &DH_GROUP14_SHA256_MODE);
    h.insert(&KEX_DH_GROUP14_SHA1, &DH_GROUP14_SHA1_MODE);
    h
});

pub trait Kex {
    fn generate_public_key(&mut self) -> Vec<u8>;
    fn generate_secret_key(&mut self, public_key: &[u8]) -> Vec<u8>;
    fn get_public_key(&self) -> Vec<u8>;
}
