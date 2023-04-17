use crate::{packet::PacketHandler, session::Session};

pub struct KexState {
    
}

pub fn recv_msg_kexinit(packet_handler: &mut PacketHandler, session: &mut Session) {
    println!("enter recv_msg_kexinit");
}
