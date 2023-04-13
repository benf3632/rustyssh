use crate::kex::recv_msg_kexinit;
use crate::msg::SSHMsg;
use crate::packet::PacketType;

pub const server_packettypes: [PacketType; 1] = [PacketType {
    msg_type: SSHMsg::KEXINIT,
    handler: &recv_msg_kexinit,
}];
