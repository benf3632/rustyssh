use log::{debug, trace};
use rand::RngCore;
use std::time::Instant;

use crate::{
    msg::SSHMsg,
    namelist::{Name, CIPHER_ORDER, COMPRESSION_ORDER, HMAC_ORDER, KEX_ORDER, SIGNATURE_ORDER},
    session::SessionHandler,
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
            panic!("Recieved already kexinit message");
        }

        self.read_kexinit_algos();

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

        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("Failed to encrypt payload");

        packet.set_pos(0);

        self.packet_handler.enqueue_packet(packet);

        self.session.kex_state.sent_kex_init = true;

        trace!("exit send_msg_kexinit");
    }
}
