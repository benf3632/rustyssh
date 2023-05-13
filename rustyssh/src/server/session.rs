use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::msg::SSHMsg;
use crate::session::SessionHandler;

pub static SERVER_PACKET_HANDLERS: Lazy<
    HashMap<SSHMsg, &(dyn Fn(&mut SessionHandler) + Send + Sync)>,
> = Lazy::new(|| {
    let mut h: HashMap<SSHMsg, &(dyn Fn(&mut SessionHandler) + Send + Sync)> = HashMap::new();
    h.insert(SSHMsg::KEXINIT, &SessionHandler::recv_msg_kexinit);
    h.insert(SSHMsg::KEXDHINIT, &SessionHandler::recv_msg_kex_dh_init);
    h.insert(SSHMsg::NEWKEYS, &SessionHandler::recv_msg_kex_newkeys);
    h
});
