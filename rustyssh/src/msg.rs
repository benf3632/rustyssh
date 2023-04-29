use core::panic;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SSHMsg {
    None = 0,
    // transport layer protocol messages refer to https://www.rfc-editor.org/rfc/rfc4253
    DISCONNECT = 1,
    IGNORE = 2,
    UNIMPLEMENTED = 3,

    // algorithem negotiation
    KEXINIT = 20,
    NEWKEYS = 21,
}

impl From<u8> for SSHMsg {
    fn from(value: u8) -> Self {
        match value {
            0 => SSHMsg::None,
            1 => SSHMsg::DISCONNECT,
            2 => SSHMsg::IGNORE,
            3 => SSHMsg::UNIMPLEMENTED,
            20 => SSHMsg::KEXINIT,
            21 => SSHMsg::NEWKEYS,
            _ => panic!("invalid msg type: {}", value),
        }
    }
}

impl From<SSHMsg> for u8 {
    fn from(value: SSHMsg) -> Self {
        match value {
            SSHMsg::None => 0,
            SSHMsg::DISCONNECT => 1,
            SSHMsg::IGNORE => 2,
            SSHMsg::UNIMPLEMENTED => 3,
            SSHMsg::KEXINIT => 20,
            SSHMsg::NEWKEYS => 21,
        }
    }
}
