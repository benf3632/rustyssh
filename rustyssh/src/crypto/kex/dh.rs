use std::ops::{Div, Sub};

use num_bigint::{BigUint, RandBigInt};

use super::Kex;

pub struct Dh {
    pub prime: BigUint,
    pub private_key: Option<BigUint>,
    pub public_key: Option<BigUint>,
    pub generator: BigUint,
}

impl Dh {
    pub fn generate_private_key(&mut self) {
        // calulcate q = (p - 1) / 2
        let prime_minus_one: BigUint = (&self.prime).sub(BigUint::new(vec![1]));
        let q: BigUint = prime_minus_one.div(BigUint::new(vec![2]));
        self.private_key = Some(rand::thread_rng().gen_biguint_range(&BigUint::new(vec![0]), &q));
    }
}

impl Kex for Dh {
    fn generate_public_key(&mut self) -> Vec<u8> {
        self.generate_private_key();
        self.public_key = Some(self.generator.modpow(
            self.private_key.as_ref().expect("private key should exist"),
            &self.prime,
        ));
        self.public_key.as_ref().unwrap().to_bytes_be()
    }
    fn generate_secret_key(&mut self, public_key: &[u8]) -> Vec<u8> {
        let public_key = BigUint::from_bytes_be(public_key);
        public_key
            .modpow(
                &self.private_key.as_ref().expect("private key should exist"),
                &self.prime,
            )
            .to_bytes_be()
    }
    fn get_public_key(&self) -> Vec<u8> {
        let empty = BigUint::new(Vec::new());
        self.public_key.as_ref().unwrap_or(&empty).to_bytes_be()
    }
}
