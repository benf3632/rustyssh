use std::{
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
};

use log::{error, info, trace, warn};
use mio::net::TcpStream;

use crate::{
    crypto::{
        cipher::{Cipher, Direction},
        kex::Kex,
    },
    msg::SSHMsg,
    namelist::Hash,
    session::Session,
    signkey::SignatureType,
    sshbuffer::SSHBuffer,
    utils::{self, error::SSHError},
};

const INIT_READBUF: usize = 128;
const PACKET_PADDING_OFF: usize = 4;
const PACKET_PAYLOAD_OFF: usize = 5;
const RECV_MAX_PACKET_LEN: u32 = 35000;

pub struct KeyContextDirectional {
    pub cipher: Box<dyn Cipher>,
    pub mac_hash: Hash,
    pub mac_key: Vec<u8>,
    pub valid: bool,
}

pub struct KeyContext {
    pub recv: KeyContextDirectional,
    pub trans: KeyContextDirectional,
    pub algo_kex: Option<Box<dyn Kex>>,
    pub algo_signature: SignatureType,
}

pub struct PacketType {
    pub msg_type: SSHMsg,
    pub handler: &'static dyn Fn(&mut PacketHandler, &mut Session),
}

pub struct PacketHandler {
    socket: TcpStream,
    write_queue: VecDeque<SSHBuffer>,
    packet_types: &'static [PacketType],

    read_buffer: Option<SSHBuffer>,

    // encrpytion
    keys: KeyContext,
    recv_seq: u32,
    trans_seq: u32,
}

impl PacketHandler {
    pub fn new(socket: TcpStream, packet_types: &'static [PacketType], keys: KeyContext) -> Self {
        Self {
            write_queue: VecDeque::new(),
            packet_types,
            keys,
            socket,
            read_buffer: None,
            recv_seq: 0,
            trans_seq: 0,
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    pub fn write_packet(&mut self) {
        while !self.write_queue.is_empty() {
            let current_buffer = self.write_queue.front_mut().unwrap();
            let written = self.socket.write(current_buffer.get_slice());
            match written {
                Ok(written) => {
                    if written == 0 {
                        panic!("Remote closed from peer");
                    } else if written != current_buffer.len() - current_buffer.pos() {
                        current_buffer.incr_pos(written);
                        return;
                    } else {
                        self.write_queue.pop_front();
                    }
                }
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    return;
                }
                Err(_) => {
                    panic!("Failed to write packet");
                }
            };
        }
    }

    pub fn read_packet(&mut self) -> Result<(Option<SSHBuffer>, usize), SSHError> {
        let recv_keys = &self.keys.recv;
        let blocksize = recv_keys.cipher.blocksize();
        if self.read_buffer.is_none()
            || self.read_buffer.as_ref().unwrap().len() < blocksize as usize
        {
            match self.read_packet_init() {
                Err(SSHError::Failure) => return Err(SSHError::Failure),
                _ => {}
            }
        }
        let readbuf = self.read_buffer.as_mut().unwrap();

        let maxlen = readbuf.len() - readbuf.pos();
        let read_length = if maxlen == 0 {
            0
        } else {
            let len = self.socket.read(readbuf.get_write_slice(maxlen));
            match len {
                Ok(len) => {
                    if len == 0 {
                        panic!("remote closed");
                    } else {
                        len
                    }
                }
                Err(e)
                    if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock =>
                {
                    return Err(SSHError::Failure);
                }
                Err(_) => {
                    panic!("There was an error reading from the main socket");
                }
            }
        };

        if read_length == maxlen {
            self.decrypt_packet()
        } else {
            Err(SSHError::Failure)
        }
    }

    pub fn decrypt_packet(&mut self) -> Result<(Option<SSHBuffer>, usize), SSHError> {
        let recv_keys = &mut self.keys.recv;
        let blocksize = recv_keys.cipher.blocksize();
        let macsize = recv_keys.mac_hash.hashsize;

        let readbuf = self.read_buffer.as_mut().unwrap();

        if recv_keys.cipher.is_aead() {
            readbuf.set_pos(0);

            let len = readbuf.len() - macsize as usize - readbuf.pos();
            let res = recv_keys
                .cipher
                .aead_crypt_in_place(readbuf.get_write_slice(len), Direction::Decrypt);
            if res.is_err() {
                panic!("Error decrypting");
            }

            readbuf.incr_pos(len);
        } else {
            readbuf.set_pos(blocksize as usize);
            let len = readbuf.len() - macsize as usize - readbuf.pos();
            let res = recv_keys
                .cipher
                .decrypt_in_place(&mut readbuf.get_write_slice(len));
            if res.is_err() {
                panic!("Error decrypting");
            }

            readbuf.incr_pos(len);

            // TODO: check mac
        }

        // get padding length
        readbuf.set_pos(PACKET_PADDING_OFF);
        let padding_len = readbuf.get_byte();

        // - 4 - 1 is for LEN and PADLEN values
        let len = readbuf.len() - padding_len as usize - 4 - 1 - macsize as usize;
        if len < 1 {
            panic!("Bad packet size {}", len);
        }

        // setup for the session.payload
        readbuf.set_pos(PACKET_PAYLOAD_OFF);
        let payload_beginning = readbuf.pos();
        readbuf.set_len(readbuf.pos() + len);
        self.recv_seq += 1;

        Ok((self.read_buffer.take(), payload_beginning))
    }

    pub fn read_packet_init(&mut self) -> Result<(), utils::error::SSHError> {
        let recv_keys = &mut self.keys.recv;
        let blocksize = recv_keys.cipher.blocksize();
        let macsize = recv_keys.mac_hash.hashsize;

        if self.read_buffer.is_none() {
            self.read_buffer = Some(SSHBuffer::new(INIT_READBUF));
        }

        let readbuf = self.read_buffer.as_mut().unwrap();

        let maxlen = blocksize as usize - readbuf.pos();
        let read = self.socket.read(&mut readbuf.get_write_slice(maxlen));

        let read_len = match read {
            Ok(len) => {
                if len == 0 {
                    // remote closed
                    panic!("remote closed");
                } else {
                    len
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock => {
                return Err(SSHError::Failure);
            }
            Err(e) => {
                panic!("Error reading {:?}", e);
            }
        };
        readbuf.incr_write_pos(read_len);

        if read_len != maxlen {
            return Err(SSHError::Failure);
        }
        readbuf.set_pos(0);

        let mut packet_length = 0;
        let mut payload_length = 0;

        if recv_keys.cipher.is_aead() {
            let payload_len = recv_keys
                .cipher
                .as_mut()
                .aead_getlength(readbuf.get_slice());
            if payload_len.is_err() {
                panic!("Error decrypting");
            }
            payload_length = payload_len.unwrap();
            packet_length = payload_length + 4 + macsize as u32;
        } else {
            let res = recv_keys
                .cipher
                .decrypt_in_place(&mut readbuf.get_write_slice(blocksize as usize));
            if res.is_err() {
                panic!("Error decrypting");
            }

            payload_length = readbuf.get_int() + 4;
            packet_length = payload_length + macsize as u32;
        }

        if packet_length > RECV_MAX_PACKET_LEN
            || payload_length < blocksize as u32
            || payload_length % blocksize as u32 != 0
        {
            panic!("Integrity error (bad packet size {}", packet_length);
        }

        if packet_length as usize > readbuf.size() {
            readbuf.resize(packet_length as usize);
        }
        readbuf.set_len(packet_length as usize);
        readbuf.set_pos(blocksize as usize);

        Ok(())
    }

    pub fn process_packet(&mut self, session: &mut Session) {
        let msg_type = SSHMsg::from_u8(session.payload.as_mut().unwrap().get_byte());

        trace!(
            "process_packet: packet type = {:?}, len = {}",
            msg_type,
            session.payload.as_mut().unwrap().len()
        );

        let mut cleanup = || {
            session.last_packet = msg_type;
            session.payload.take();
        };

        match msg_type {
            SSHMsg::IGNORE => {
                cleanup();
                return;
            }
            SSHMsg::UNIMPLEMENTED => {
                trace!("SSH_MSG_UNIMPLEMENTED");
                cleanup();
                return;
            }
            SSHMsg::DISCONNECT => {
                // TODO: Cleanup
                panic!("Disconnect received");
            }

            _ => {}
        }

        if session.require_next != SSHMsg::None {
            if session.require_next == msg_type {
                trace!("got expected packet {:?} during kexinit", msg_type);
            } else {
                if msg_type != SSHMsg::KEXINIT {
                    warn!("unknown allowed packet during kexinit");
                    // handle unimplemented
                    cleanup();
                    return;
                } else {
                    error!("disallowed packet during kexinit");
                    panic!(
                        "Unexpected packet type {:?}, expected {:?}",
                        msg_type, session.require_next
                    );
                }
            }
        }

        if session.ignore_next {
            info!("Ignoring packet, type = {:?}", msg_type);
            session.ignore_next = false;
            cleanup();
            return;
        }

        if session.require_next != SSHMsg::None && session.require_next == msg_type {
            session.require_next = SSHMsg::None;
        }

        // TODO: check for auth state when implemented
        // (self.packet_processor)(msg_type, session);
        for packet_type in self.packet_types.iter() {
            if packet_type.msg_type == msg_type {
                // let handler = packet_type.handler;
                (packet_type.handler)(self, session);
                session.last_packet = msg_type;
                session.payload.take();
                return;
            }
        }

        // TODO: recv unimplemented

        unimplemented!();
    }

    // write queue methods
    pub fn enqueue_packet(&mut self, packet: SSHBuffer) {
        self.write_queue.push_back(packet);
    }

    pub fn is_write_queue_empty(&self) -> bool {
        self.write_queue.is_empty()
    }
}
