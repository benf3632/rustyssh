use std::{collections::HashMap, io::Read};

use num_bigint::BigUint;
use once_cell::sync::Lazy;
use ring::signature::{KeyPair, RsaEncoding, RsaKeyPair, VerificationAlgorithm, RSA_PKCS1_SHA256};

use crate::{namelist::Name, sshbuffer::SSHBuffer, utils::error::SSHError};

pub enum SignatureKeyPair {
    Rsa(RsaKeyPair),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum SignatureType {
    Rsa,
    Ecdsa,
    Ed25519,
}

pub struct SignatureMode {
    padding_alg: Option<&'static dyn RsaEncoding>,
    sig_type: SignatureType,
}

// pub static SSH_RSA_SIG: SignatureMode = SignatureMode {
//     sig_type: SignatureType::Rsa,
//     padding_alg: Some(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
// };

pub static RSA_SHA2_256_SIG: SignatureMode = SignatureMode {
    sig_type: SignatureType::Rsa,
    padding_alg: Some(&RSA_PKCS1_SHA256),
};

// pub const SSH_RSA: Name = Name("ssh-rsa");
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");

pub static SIGNATURES: Lazy<HashMap<&'static Name, &'static SignatureMode>> = Lazy::new(|| {
    let mut h: HashMap<&'static Name, &'static SignatureMode> = HashMap::new();
    // h.insert(&SSH_RSA, &SSH_RSA_SIG);
    h.insert(&RSA_SHA2_256, &RSA_SHA2_256_SIG);
    h
});

pub type HostKeys = HashMap<SignatureType, SignatureKeyPair>;

pub fn create_signtaure(
    host_keys: &HostKeys,
    sig_mode: &SignatureMode,
    message: &[u8],
) -> Result<Vec<u8>, SSHError> {
    let sig_key_pair = host_keys
        .get(&sig_mode.sig_type)
        .expect("No host key available for signature type");
    let rng = ring::rand::SystemRandom::new();
    let mut signature = Vec::new();
    match sig_key_pair {
        SignatureKeyPair::Rsa(rsa_key_pair) => rsa_key_pair
            .sign(
                sig_mode.padding_alg.unwrap(),
                &rng,
                &message,
                &mut signature,
            )
            .map_err(|_| SSHError::Failure)?,
    };
    Ok(signature)
}

pub fn get_public_host_key(
    host_keys: &HostKeys,
    sig_mode: &SignatureMode,
) -> Result<SSHBuffer, SSHError> {
    let sig_key_pair = host_keys
        .get(&sig_mode.sig_type)
        .expect("No host key available for signature type");
    match sig_key_pair {
        SignatureKeyPair::Rsa(rsa_key_pair) => {
            let rsa_public_key = rsa_key_pair.public_key();
            let exponent = rsa_public_key.exponent().big_endian_without_leading_zero();
            let modulus = rsa_public_key.modulus().big_endian_without_leading_zero();
            let host_key_identifier = "ssh-rsa";

            // adding 4 for for len of string, mpint and mpint
            // string    "ssh-rsa"
            // mpint     e
            // mpint     n
            let mut host_key_buffer = SSHBuffer::new(
                host_key_identifier.len() + 4 + exponent.len() + 4 + modulus.len() + 4,
            );
            let exponent = BigUint::from_bytes_be(exponent);
            let modulus = BigUint::from_bytes_be(modulus);
            host_key_buffer.put_string(host_key_identifier.as_bytes(), host_key_identifier.len());
            host_key_buffer.put_mpint(&exponent);
            host_key_buffer.put_mpint(&modulus);
            host_key_buffer.set_pos(0);

            Ok(host_key_buffer)
        }
    }
}

pub fn load_host_keys() -> HostKeys {
    let mut file = std::fs::File::open("ssh_host_rsa_key").unwrap();
    let mut rsa_key_file_contents = Vec::new();
    file.read_to_end(&mut rsa_key_file_contents).unwrap();

    let rsa_key = RsaKeyPair::from_der(&rsa_key_file_contents).unwrap();

    let mut host_keys: HostKeys = HostKeys::new();

    host_keys.insert(SignatureType::Rsa, SignatureKeyPair::Rsa(rsa_key));
    host_keys
}
