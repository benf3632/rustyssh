use log::{debug, trace};
use rand::RngCore;
use std::time::Instant;

use crate::{
    msg::SSHMsg,
    namelist::{CIPHER_ORDER, COMPRESSION_ORDER, HMAC_ORDER, KEX_ORDER, SIGNATURE_ORDER},
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

impl SessionHandler {
    pub fn recv_msg_kexinit(&mut self) {
        trace!("enter recv_msg_kexinit");
        if !self.session.kex_state.sent_kex_init {
            debug!("Sending KEXINIT");
            self.send_msg_kexinit();
        }

        debug!("payload: {:?}", self.session.payload);

        trace!("exit recv_msg_kexinit");
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
        debug!("{:?}", packet);

        self.packet_handler.enqueue_packet(packet);

        self.session.kex_state.sent_kex_init = true;

        trace!("exit send_msg_kexinit");
    }
}
