use std::{collections::HashMap, io::Read, unimplemented};

use log::{debug, error};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use pkcs1::der::Encode;
use ring::{
    rsa::{KeyPair, PublicKeyComponents},
    signature::{
        RsaEncoding, UnparsedPublicKey, VerificationAlgorithm,
        RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
    },
};

use crate::{namelist::Name, sshbuffer::SSHBuffer, utils::error::SSHError};

pub enum SignatureKeyPair {
    Rsa(ring::rsa::KeyPair),
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
    sig_identifier: &'static str,
    sig_verifier: &'static dyn VerificationAlgorithm,
}

pub static SSH_RSA_SIG: SignatureMode = SignatureMode {
    sig_type: SignatureType::Rsa,
    padding_alg: None,
    sig_verifier: &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    sig_identifier: "ssh-rsa",
};

pub static RSA_SHA2_256_SIG: SignatureMode = SignatureMode {
    sig_type: SignatureType::Rsa,
    padding_alg: Some(&RSA_PKCS1_SHA256),
    sig_identifier: "rsa-sha2-256",
    sig_verifier: &RSA_PKCS1_2048_8192_SHA256,
};

pub const SSH_RSA: Name = Name("ssh-rsa");
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");

pub static SIGNATURES: Lazy<HashMap<&'static Name, &'static SignatureMode>> = Lazy::new(|| {
    let mut h: HashMap<&'static Name, &'static SignatureMode> = HashMap::new();
    h.insert(&SSH_RSA, &SSH_RSA_SIG);
    h.insert(&RSA_SHA2_256, &RSA_SHA2_256_SIG);
    h
});

pub type HostKeys = HashMap<SignatureType, SignatureKeyPair>;

pub fn create_signtaure(
    host_keys: &HostKeys,
    sig_mode: &SignatureMode,
    message: &[u8],
) -> Result<SSHBuffer, SSHError> {
    let sig_key_pair = host_keys
        .get(&sig_mode.sig_type)
        .expect("No host key available for signature type");
    let rng = ring::rand::SystemRandom::new();
    match sig_key_pair {
        SignatureKeyPair::Rsa(rsa_key_pair) => {
            let mut signature = Vec::new();
            signature.resize(rsa_key_pair.public().modulus_len(), 0);
            rsa_key_pair
                .sign(
                    sig_mode.padding_alg.unwrap(),
                    &rng,
                    &message,
                    &mut signature,
                )
                .map_err(|_| SSHError::Failure)?;
            let signature_identifier = sig_mode.sig_identifier;

            let mut encoded_signature =
                SSHBuffer::new(signature_identifier.len() + 4 + signature.len() + 4);
            encoded_signature
                .put_string(signature_identifier.as_bytes(), signature_identifier.len());
            encoded_signature.put_string(&signature, signature.len());
            encoded_signature.set_pos(0);
            Ok(encoded_signature)
        }
    }
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
            let rsa_public_key_components: PublicKeyComponents<Vec<u8>> =
                PublicKeyComponents::from(rsa_key_pair.public());
            let exponent = rsa_public_key_components.e;
            let modulus = rsa_public_key_components.n;
            let host_key_identifier = "ssh-rsa";

            // adding 4 for for len of string, mpint and mpint
            // string    "ssh-rsa"
            // mpint     e
            // mpint     n
            let mut host_key_buffer = SSHBuffer::new(
                host_key_identifier.len() + 4 + exponent.len() + 1 + 4 + modulus.len() + 1 + 4,
            );
            let exponent = BigUint::from_bytes_be(&exponent);
            let modulus = BigUint::from_bytes_be(&modulus);
            host_key_buffer.put_string(host_key_identifier.as_bytes(), host_key_identifier.len());
            host_key_buffer.put_mpint(&exponent);
            host_key_buffer.put_mpint(&modulus);
            host_key_buffer.set_pos(0);

            Ok(host_key_buffer)
        }
    }
}

pub fn parse_and_verify_public_key(
    unparsed_public_key: &mut SSHBuffer,
    msg: &[u8],
    sig_ident: &[u8],
    sig: &[u8],
) -> Result<(), SSHError> {
    let (pub_key_sig_identifier, _) = unparsed_public_key.get_string();
    debug!("len: {}", pub_key_sig_identifier.len());
    let pub_key_sig_identifier_str =
        std::str::from_utf8(&pub_key_sig_identifier).map_err(|_| SSHError::Failure)?;
    debug!("key type: {}", pub_key_sig_identifier_str);

    let pub_key_sig_ident_name = Name(&pub_key_sig_identifier_str);

    let sig_ident_str = std::str::from_utf8(&sig_ident).map_err(|_| SSHError::Failure)?;
    let sig_ident_name = Name(&sig_ident_str);

    if sig_ident_name != pub_key_sig_ident_name {
        error!("Signature type is different from the supplied public key");
        return Err(SSHError::Failure);
    }

    let sig_mode = SIGNATURES
        .get(&sig_ident_name)
        .ok_or_else(|| SSHError::Failure)?;

    match sig_mode.sig_type {
        SignatureType::Rsa => {
            let rsa_exponent = unparsed_public_key.get_mpint().to_bytes_be();
            let rsa_modulus = unparsed_public_key.get_mpint().to_bytes_be();

            let rsa_public_key = pkcs1::RsaPublicKey {
                modulus: pkcs1::UintRef::new(&rsa_modulus).map_err(|_| SSHError::Failure)?,
                public_exponent: pkcs1::UintRef::new(&rsa_exponent)
                    .map_err(|_| SSHError::Failure)?,
            };

            let encoded_len: u32 = rsa_public_key.encoded_len().unwrap().into();

            let mut rsa_encoded = vec![0; encoded_len as usize];
            rsa_public_key.encode_to_slice(&mut rsa_encoded).unwrap();
            let public_key = UnparsedPublicKey::new(sig_mode.sig_verifier, rsa_encoded);
            public_key.verify(msg, sig).map_err(|_| SSHError::Failure)?;
        }
        _ => unimplemented!(),
    };

    Ok(())
}

pub fn load_host_keys() -> HostKeys {
    let mut file = std::fs::File::open("ssh_host_rsa_key").unwrap();
    let mut rsa_key_file_contents = Vec::new();
    file.read_to_end(&mut rsa_key_file_contents).unwrap();

    let rsa_key = KeyPair::from_pkcs8(&rsa_key_file_contents).unwrap();

    let mut host_keys: HostKeys = HostKeys::new();

    host_keys.insert(SignatureType::Rsa, SignatureKeyPair::Rsa(rsa_key));
    host_keys
}
