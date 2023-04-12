pub enum SSHMsg {
    // transport layer protocol messages refer to https://www.rfc-editor.org/rfc/rfc4253
    DISCONNECT = 1,
    IGNORE = 2,
    UNIMPLEMENTED = 3,

    // alogrithem negotiation
    KEXINIT = 20,
    NEWKEYS = 21,
}
