use core::panic;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SSHMsg {
    None = 0,
    // transport layer protocol messages refer to https://www.rfc-editor.org/rfc/rfc4253
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,

    // service
    ServiceRequest = 5,
    ServiceAccept = 6,

    // algorithem negotiation
    KexInit = 20,
    NewKeys = 21,

    // kex
    KexDHInit = 30,
    KexDHReply = 31,

    // user authentication
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,

    // auth public key
    UserauthPKOk = 60,
}

impl From<u8> for SSHMsg {
    fn from(value: u8) -> Self {
        match value {
            0 => SSHMsg::None,
            1 => SSHMsg::Disconnect,
            2 => SSHMsg::Ignore,
            3 => SSHMsg::Unimplemented,
            5 => SSHMsg::ServiceRequest,
            6 => SSHMsg::ServiceAccept,
            20 => SSHMsg::KexInit,
            21 => SSHMsg::NewKeys,
            30 => SSHMsg::KexDHInit,
            31 => SSHMsg::KexDHReply,
            50 => SSHMsg::UserauthRequest,
            51 => SSHMsg::UserauthFailure,
            52 => SSHMsg::UserauthSuccess,
            53 => SSHMsg::UserauthBanner,
            60 => SSHMsg::UserauthPKOk,
            _ => panic!("invalid msg type: {}", value),
        }
    }
}

impl From<SSHMsg> for u8 {
    fn from(value: SSHMsg) -> Self {
        match value {
            SSHMsg::None => 0,
            SSHMsg::Disconnect => 1,
            SSHMsg::Ignore => 2,
            SSHMsg::Unimplemented => 3,
            SSHMsg::ServiceRequest => 5,
            SSHMsg::ServiceAccept => 6,
            SSHMsg::KexInit => 20,
            SSHMsg::NewKeys => 21,
            SSHMsg::KexDHInit => 30,
            SSHMsg::KexDHReply => 31,
            SSHMsg::UserauthRequest => 50,
            SSHMsg::UserauthFailure => 51,
            SSHMsg::UserauthSuccess => 52,
            SSHMsg::UserauthBanner => 53,
            SSHMsg::UserauthPKOk => 60,
        }
    }
}
