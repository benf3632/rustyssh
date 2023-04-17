use core::panic;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SSHMsg {
    None = 0,
    // transport layer protocol messages refer to https://www.rfc-editor.org/rfc/rfc4253
    DISCONNECT = 1,
    IGNORE = 2,
    UNIMPLEMENTED = 3,

    // alogrithem negotiation
    KEXINIT = 20,
    NEWKEYS = 21,
}

impl SSHMsg {
    pub fn from_u8(value: u8) -> SSHMsg {
        match value {
            0 => SSHMsg::None,
            1 => SSHMsg::DISCONNECT,
            2 => SSHMsg::IGNORE,
            3 => SSHMsg::UNIMPLEMENTED,
            20 => SSHMsg::KEXINIT,
            21 => SSHMsg::NEWKEYS,
            _ => panic!("Unimplemented msg: {}", value),
        }
    }
}
