use log::{debug, trace};
use num_bigint::BigUint;
use rand::RngCore;
use ring::digest::digest;
use std::time::Instant;

use crate::{
    crypto::{
        cipher::CIPHERS,
        kex::{self, Kex, KexType, KEXS},
        signature::{create_signtaure, get_public_host_key, SIGNATURES},
    },
    msg::SSHMsg,
    namelist::{Name, CIPHER_ORDER, COMPRESSION_ORDER, HMAC_ORDER, KEX_ORDER, SIGNATURE_ORDER},
    packet::{KeyContext, KeyContextDirectional},
    session::SessionHandler,
    sshbuffer::SSHBuffer,
};

const COOKIE_LEN: usize = 16;

pub struct KexState {
    pub sent_kex_init: bool,
    pub recv_kex_init: bool,
    pub them_first_follow: bool,
    pub sent_new_keys: bool,
    pub recv_new_keys: bool,
    pub done_first_kext: bool,
    pub our_first_follow_matches: bool,
    pub last_kex_time: Instant,
    pub data_trans: usize,
    pub data_recv: usize,
}

impl Default for KexState {
    fn default() -> Self {
        Self {
            sent_kex_init: false,
            recv_kex_init: false,
            them_first_follow: false,
            sent_new_keys: false,
            recv_new_keys: false,
            done_first_kext: false,
            our_first_follow_matches: false,
            last_kex_time: Instant::now(),
            data_trans: 0,
            data_recv: 0,
        }
    }
}

fn match_algo<'a>(local_algos: &'a [Name], remote_algos: &Vec<u8>) -> Option<&'a Name> {
    let remote_algos = std::str::from_utf8(&remote_algos).expect("Invalid namelist");
    let remote_algos_list = remote_algos.split(",");

    for remote_algo_name in remote_algos_list {
        for local_algo_name in local_algos {
            if local_algo_name == remote_algo_name {
                return Some(local_algo_name);
            }
        }
    }
    None
}

impl SessionHandler {
    pub fn recv_msg_kexinit(&mut self) {
        trace!("enter recv_msg_kexinit");

        if !self.session.kex_state.sent_kex_init {
            debug!("Sending KEXINIT");
            self.send_msg_kexinit();
        }

        if self.session.kex_state.recv_kex_init {
            panic!("Already recieved kexinit message");
        }

        self.read_kexinit_algos();

        if self.session.kex_hash_buffer.is_none() {
            // calculate the kex hash buffer len
            //   string    V_C, the client's identification string (CR and LF
            //             excluded)
            //   string    V_S, the server's identification string (CR and LF
            //             excluded)
            //   string    I_C, the payload of the client's SSH_MSG_KEXINIT
            //   string    I_S, the payload of the server's SSH_MSG_KEXINIT
            //   4 * 4 is for the strings length field
            let kex_hash_buffer_len = self
                .session
                .identification
                .as_ref()
                .expect("remote identification should exist by now")
                .len()
                + self.session.local_ident.len()
                + self
                    .session
                    .local_kex_init_message
                    .as_ref()
                    .expect("our kex init should have been sent")
                    .len()
                + (self
                    .session
                    .payload
                    .as_ref()
                    .expect("payload should exist")
                    .len()
                    - self.session.payload_beginning)
                + 4 * 4;

            self.session.kex_hash_buffer = Some(SSHBuffer::new(kex_hash_buffer_len));
        }

        let kex_hash_buffer = self
            .session
            .kex_hash_buffer
            .as_mut()
            .expect("kex hash buffer should exist");

        let remote_ident = self
            .session
            .identification
            .as_ref()
            .expect("remote identification should exist");

        let local_kex_init_message = self
            .session
            .local_kex_init_message
            .as_ref()
            .expect("local kex message should exist");

        let payload = self.session.payload.as_mut().expect("payload should exist");
        payload.set_pos(self.session.payload_beginning);

        if self.session.is_server {
            // put client's identification string
            kex_hash_buffer.put_string(remote_ident.as_bytes(), remote_ident.len());

            // put server's identification string
            kex_hash_buffer.put_string(
                self.session.local_ident.as_bytes(),
                self.session.local_ident.len(),
            );

            // put client's kex init message
            kex_hash_buffer
                .put_string(&payload[..], payload.len() - self.session.payload_beginning);

            // put server's kex init message
            kex_hash_buffer.put_string(&local_kex_init_message[..], local_kex_init_message.len());

            // put server's host key
            let newkeys = self.session.newkeys.as_ref().expect("newkeys should exist");
            let host_key = get_public_host_key(
                &self.session.hostkeys,
                newkeys
                    .host_signature
                    .as_ref()
                    .expect("host signature should exist"),
            )
            .expect("public host key should exist");

            // pust server's host key
            kex_hash_buffer.resize(kex_hash_buffer.len() + host_key.len() + 4);
            kex_hash_buffer.put_string(&host_key[..], host_key.len());

            self.session.require_next = SSHMsg::KEXDHINIT;
        } else {
            // put client's identification string
            kex_hash_buffer.put_string(
                self.session.local_ident.as_bytes(),
                self.session.local_ident.len(),
            );

            // put server's identification string
            kex_hash_buffer.put_string(remote_ident.as_bytes(), remote_ident.len());

            // put client's kex init message
            kex_hash_buffer.put_string(&local_kex_init_message[..], local_kex_init_message.len());

            // put server's kex init message
            kex_hash_buffer
                .put_string(&payload[..], payload.len() - self.session.payload_beginning);

            // TODO: send KEXDH_INIT
            self.session.require_next = SSHMsg::KEXDHREPLY;
        }
        self.session.kex_state.recv_kex_init = true;

        trace!("exit recv_msg_kexinit");
    }

    pub fn read_kexinit_algos(&mut self) {
        let payload = self.session.payload.as_mut().expect("Expected payload");

        // skip cookie, only used for the hash
        payload.incr_pos(COOKIE_LEN);

        // match kex algos
        let (kex_algos, _) = payload.get_string();
        let kex_name_match =
            match_algo(KEX_ORDER, &kex_algos).expect("No matching kex algorithms found");
        debug!("KEX: {:?}", kex_name_match);

        // match server host key algos
        let (server_host_algos, _) = payload.get_string();
        let server_host_match = match_algo(SIGNATURE_ORDER, &server_host_algos)
            .expect("No matching server host keys algorithms found");
        debug!("SERVER_HOST_KEY: {:?}", server_host_match);

        // match ciphers client to server algos
        let (ciphers_c2s_algos, _) = payload.get_string();
        let ciphers_c2s_match = match_algo(CIPHER_ORDER, &ciphers_c2s_algos)
            .expect("No matching encryption ctos algorithms found");
        debug!("CIPHER_C2S: {:?}", ciphers_c2s_match);

        // match ciphers server to client algos
        let (ciphers_s2c_algos, _) = payload.get_string();
        let ciphers_s2c_match = match_algo(CIPHER_ORDER, &ciphers_s2c_algos)
            .expect("No matching encryption ctos algorithms found");
        debug!("CIPHER_S2C: {:?}", ciphers_s2c_match);

        // match mac client to server algos
        let (macs_c2s_algos, _) = payload.get_string();
        let macs_c2s_match = match_algo(HMAC_ORDER, &macs_c2s_algos)
            .expect("No matching macs ctos algorithms found");
        debug!("MAC_C2S: {:?}", macs_c2s_match);

        // match mac server to client algos
        let (macs_s2c_algos, _) = payload.get_string();
        let macs_s2c_match = match_algo(HMAC_ORDER, &macs_s2c_algos)
            .expect("No matching macs ctos algorithms found");
        debug!("MAC_S2C: {:?}", macs_s2c_match);

        // match compression client to server algos
        let (compression_c2s_algos, _) = payload.get_string();
        let compression_c2s_match = match_algo(COMPRESSION_ORDER, &compression_c2s_algos)
            .expect("No matching compression ctos algorithms found");
        debug!("COMPRESSION_C2S: {:?}", compression_c2s_match);

        // match compression server to client algos
        let (compression_s2c_algos, _) = payload.get_string();
        let compression_s2c_match = match_algo(COMPRESSION_ORDER, &compression_s2c_algos)
            .expect("No matching compression ctos algorithms found");
        debug!("COMPRESSION_S2C: {:?}", compression_s2c_match);

        let kex_mode = *KEXS.get(kex_name_match).unwrap();
        let host_signature = *SIGNATURES.get(server_host_match).unwrap();
        let cipher_c2s = *CIPHERS.get(ciphers_c2s_match).unwrap();
        let cipher_s2c = *CIPHERS.get(ciphers_s2c_match).unwrap();
        let mac_c2s = if cipher_c2s.is_aead() {
            Some(cipher_c2s.aead_mac())
        } else {
            None
        };
        let mac_s2c = if cipher_s2c.is_aead() {
            Some(cipher_s2c.aead_mac())
        } else {
            None
        };

        let new_keys = KeyContext {
            recv: KeyContextDirectional {
                cipher: None,
                cipher_mode: Some(cipher_c2s),
                mac_hash: mac_c2s,
                mac_key: None,
                valid: false,
            },
            trans: KeyContextDirectional {
                cipher: None,
                cipher_mode: Some(cipher_s2c),
                mac_hash: mac_s2c,
                mac_key: None,
                valid: false,
            },
            kex_mode: Some(kex_mode.clone()),
            host_signature: Some(host_signature),
        };

        self.session.newkeys = Some(new_keys);

        // skip languages namelist
        payload.get_string();
        payload.get_string();

        let is_first_kex_packet_follows = payload.get_bool();
        self.session.kex_state.them_first_follow = is_first_kex_packet_follows;
        if is_first_kex_packet_follows {
            self.session.ignore_next = true;
        }

        // reserved for futurue extensions
        payload.get_int();
    }

    pub fn send_msg_kexinit(&mut self) {
        trace!("enter send_msg_kexinit");

        let write_payload = &mut self.session.write_payload;
        write_payload.set_len(0);
        write_payload.put_byte(SSHMsg::KEXINIT.into());

        // add cookie which is random 16 bytes
        rand::thread_rng().fill_bytes(&mut write_payload[..COOKIE_LEN]);
        write_payload.incr_write_pos(COOKIE_LEN);

        // push kex_algorithms
        write_payload.put_namelist(KEX_ORDER);

        // push server_host_key_algorithms
        write_payload.put_namelist(SIGNATURE_ORDER);

        // push encryption_algorithms_client_to_server
        write_payload.put_namelist(CIPHER_ORDER);

        // push encryption_algorithms_server_to_client
        write_payload.put_namelist(CIPHER_ORDER);

        // push mac_algorithms_client_to_server
        write_payload.put_namelist(HMAC_ORDER);

        // push mac_algorithms_server_to_client
        write_payload.put_namelist(HMAC_ORDER);

        // push compression_algorithms_client_to_server
        write_payload.put_namelist(COMPRESSION_ORDER);

        // push compression_algorithms_server_to_client
        write_payload.put_namelist(COMPRESSION_ORDER);

        // push languages_client_to_server
        write_payload.put_string("".as_bytes(), 0);

        // push languages_server_to_client
        write_payload.put_string("".as_bytes(), 0);

        // push first_kex_packet_follows
        write_payload.put_bool(false);

        // push resereved
        write_payload.put_int(0);

        write_payload.set_pos(0);

        self.session.local_kex_init_message = Some(write_payload.clone());

        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("Failed to encrypt payload");

        packet.set_pos(0);

        self.packet_handler.enqueue_packet(packet);

        self.session.kex_state.sent_kex_init = true;

        trace!("exit send_msg_kexinit");
    }

    pub fn send_msg_kex_dh_reply(&mut self) {
        let write_payload = &mut self.session.write_payload;
        write_payload.set_len(0);
        write_payload.set_pos(0);

        let payload = self.session.payload.as_mut().expect("payload should exist");
        let newkeys = self.session.newkeys.as_mut().expect("newkeys should exist");
        let host_signature = newkeys
            .host_signature
            .as_ref()
            .expect("host signature should exist");
        let kex_mode = newkeys.kex_mode.as_mut().expect("kex mode should exist");
        let kex_hash_buffer = self
            .session
            .kex_hash_buffer
            .as_mut()
            .expect("kex hash buffer should exist");

        match kex_mode.kex_type {
            KexType::DH(dh) => {
                let remote_public = payload.get_mpint();
                let mut dh = dh.clone();
                dh.generate_public_key();
                let local_public = dh.get_public_key();
                let host_key = get_public_host_key(&self.session.hostkeys, host_signature)
                    .expect("host key should exist");
                write_payload.set_len(1 + local_public.len() + 4 + host_key.len() + 4);

                // put message type and host key
                write_payload.put_byte(SSHMsg::KEXDHREPLY.into());
                write_payload.put_string(&host_key[..], host_key.len());

                // put f (local public key)
                let local_public = BigUint::from_bytes_be(&local_public);
                write_payload.put_mpint(&local_public);

                // generate secret key and signtaure
                let secret_key = dh.generate_secret_key(&remote_public.to_bytes_be());

                // resize to fit 3 mpints
                kex_hash_buffer.resize(
                    remote_public.to_bytes_le().len()
                        + 4
                        + local_public.to_bytes_be().len()
                        + 4
                        + secret_key.len()
                        + 4,
                );
                // put e (client's public key) in kex hash
                kex_hash_buffer.put_mpint(&remote_public);
                // put f (server's public key) in kex hash
                kex_hash_buffer.put_mpint(&local_public);
                // put seceret key in kex hash
                kex_hash_buffer.put_mpint(&BigUint::from_bytes_be(&secret_key));
                kex_hash_buffer.set_pos(0);
                let signature = create_signtaure(
                    &self.session.hostkeys,
                    &host_signature,
                    &kex_hash_buffer[..],
                )
                .expect("signtaure should be valid");

                // store secret key for generating keys
                self.session.secret_key = Some(secret_key);

                // if it is the first key exchange we generate the exchange hash
                if self.session.exchange_hash.is_none() {
                    let exchange_hash = digest(
                        kex_mode
                            .digest
                            .as_ref()
                            .expect("kex mode digest should exist"),
                        &kex_hash_buffer[..],
                    );
                    self.session.exchange_hash = Some(exchange_hash.as_ref().to_vec());
                }

                // remove kex hash buffer
                self.session.kex_hash_buffer.take();

                // put signtaure of exchange hash
                write_payload.put_string(&signature, signature.len());
                write_payload.set_pos(0);
            }
            KexType::ECDH => unimplemented!(),
        };

        // encrypt and enqueue packet for sending
        let mut packet = self
            .packet_handler
            .encrypt_packet(&write_payload)
            .expect("packet encryption should succeed");
        packet.set_pos(0);
        self.packet_handler.enqueue_packet(packet);
    }

    pub fn recv_msg_kex_dh_init(&mut self) {
        trace!("enter recv_msg_kex_dh_init");
        self.send_msg_kex_dh_reply();

        self.send_msg_kex_newkeys();

        self.session.require_next = SSHMsg::NEWKEYS;

        trace!("exit recv_msg_kex_dh_init");
    }

    pub fn send_msg_kex_newkeys(&mut self) {
        let write_payload = &mut self.session.write_payload;
        write_payload.set_len(1);
        write_payload.set_pos(0);
        write_payload.put_byte(SSHMsg::NEWKEYS.into());
        let mut packet = self
            .packet_handler
            .encrypt_packet(&write_payload)
            .expect("packet encryption should succeed");
        packet.set_pos(0);
        self.packet_handler.enqueue_packet(packet);

        self.session.kex_state.done_first_kext = true;

        self.generate_new_keys();
        self.switch_keys();
    }

    pub fn generate_new_keys(&mut self) {}
    pub fn switch_keys(&mut self) {}
}
