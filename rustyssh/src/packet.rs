use std::{
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
};

use mio::net::TcpStream;

use crate::{
    crypto::cipher::Direction,
    msg::SSHMsg,
    session::Session,
    sshbuffer::SSHBuffer,
    utils::{self, error::SSHError},
};

const INIT_READBUF: usize = 128;
const PACKET_PADDING_OFF: usize = 4;
const PACKET_PAYLOAD_OFF: usize = 5;
const RECV_MAX_PACKET_LEN: u32 = 35000;

pub struct PacketType {
    pub msg_type: SSHMsg,
    pub handler: &'static dyn Fn(&mut PacketHandler, &mut Session),
}

pub struct PacketHandler {
    write_queue: VecDeque<SSHBuffer>,
    packet_types: &'static [PacketType],
}

impl PacketHandler {
    pub fn new(packet_types: &'static [PacketType]) -> Self {
        Self {
            write_queue: VecDeque::new(),
            packet_types,
        }
    }

    pub fn write_packet(&mut self, socket: &mut TcpStream) {
        while !self.write_queue.is_empty() {
            let current_buffer = self.write_queue.front_mut().unwrap();
            current_buffer.set_pos(0);
            let written = socket.write(current_buffer.get_slice());
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

    pub fn read_packet(&mut self, session: &mut Session) {
        let recv_keys = &session.keys.as_ref().unwrap().recv;
        let blocksize = recv_keys.cipher.blocksize;
        if session.readbuf.is_none() || session.readbuf.as_ref().unwrap().len() < blocksize as usize
        {
            match self.read_packet_init(session) {
                Err(SSHError::Failure) => {
                    return;
                }
                _ => {}
            }
        }
        let readbuf = session.readbuf.as_mut().unwrap();

        let maxlen = readbuf.len() - readbuf.pos();
        let read_length = if maxlen == 0 {
            0
        } else {
            let len = session.socket.read(readbuf.get_write_slice(maxlen));
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
                    return;
                }
                Err(_) => {
                    panic!("There was an error reading from the main socket");
                }
            }
        };

        if read_length == maxlen {
            self.decrypt_packet(session);
        }
    }

    pub fn decrypt_packet(&mut self, session: &mut Session) {
        let recv_keys = &mut session.keys.as_mut().unwrap().recv;
        let blocksize = recv_keys.cipher.blocksize;
        let macsize = recv_keys.mac_hash.hashsize;

        let readbuf = session.readbuf.as_mut().unwrap();

        if recv_keys.cipher.crypt_mode.is_aead() {
            readbuf.set_pos(0);

            let len = readbuf.len() - macsize as usize - readbuf.pos();
            let res = recv_keys
                .cipher
                .crypt_mode
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
                .crypt_mode
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
        session.payload_beginning = readbuf.pos();
        readbuf.set_len(readbuf.pos() + len);

        session.payload = session.readbuf.take();

        session.recvseq += 1;
    }

    pub fn read_packet_init(
        &mut self,
        session: &mut Session,
    ) -> Result<(), utils::error::SSHError> {
        let recv_keys = &mut session.keys.as_mut().unwrap().recv;
        let blocksize = recv_keys.cipher.blocksize;
        let macsize = recv_keys.mac_hash.hashsize;

        if session.readbuf.is_none() {
            session.readbuf = Some(SSHBuffer::new(INIT_READBUF));
        }

        let readbuf = session.readbuf.as_mut().unwrap();

        let maxlen = blocksize as usize - readbuf.pos();
        let read = session.socket.read(&mut readbuf.get_write_slice(maxlen));

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

        if recv_keys.cipher.crypt_mode.is_aead() {
            let payload_len = recv_keys
                .cipher
                .crypt_mode
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
                .crypt_mode
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

        println!(
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
                println!("SSH_MSG_UNIMPLEMENTED");
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
                println!("got expected packet {:?} during kexinit", msg_type);
            } else {
                if msg_type != SSHMsg::KEXINIT {
                    println!("unknown allowed packet during kexinit");
                    // handle unimplemented
                    cleanup();
                    return;
                } else {
                    println!("disallowed packet during kexinit");
                    panic!(
                        "Unexpected packet type {:?}, expected {:?}",
                        msg_type, session.require_next
                    );
                }
            }
        }

        if session.ignore_next {
            println!("Ignoring packet, type = {:?}", msg_type);
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
