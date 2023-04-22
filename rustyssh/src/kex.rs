use log::{debug, error, info, trace, warn};
use std::time::Instant;

use crate::{
    packet::PacketHandler,
    session::{Session, SessionHandler},
};

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

pub fn recv_msg_kexinit(packet_handler: &mut PacketHandler, session: &mut Session) {
    debug!("enter recv_msg_kexinit");
}
