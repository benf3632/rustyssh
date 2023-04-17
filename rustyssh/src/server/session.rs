use crate::kex::recv_msg_kexinit;
use crate::msg::SSHMsg;
use crate::packet::PacketType;
use crate::session::Session;

pub const SERVER_PACKET_TYPES: [PacketType; 1] = [PacketType {
    msg_type: SSHMsg::KEXINIT,
    handler: &recv_msg_kexinit,
}];
