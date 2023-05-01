pub mod dh;
pub mod dh_groups;

pub enum KexMode {
    DH,
    ECDH,
}

pub trait Kex {
    fn generate_public_key(&mut self) -> Vec<u8>;
    fn generate_secret_key(&mut self, public_key: &[u8]) -> Vec<u8>;
    fn get_public_key(&self) -> Vec<u8>;
}
