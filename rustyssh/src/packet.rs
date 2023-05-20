use std::{
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
};

use log::{debug, trace};
use mio::net::TcpStream;
use rand::RngCore;

use crate::{
    crypto::{
        cipher::{none::NoneCipher, Cipher, Direction},
        hmac::{compute_hmac, verify_hmac, Hmac, HMAC_NONE},
        kex::KexMode,
        signature::SignatureMode,
    },
    sshbuffer::SSHBuffer,
    utils::{self, error::SSHError},
};

const INIT_READBUF: usize = 128;
const PACKET_PADDING_OFF: usize = 4;
const PACKET_PAYLOAD_OFF: usize = 5;
const RECV_MAX_PACKET_LEN: u32 = 35000;

const PACKET_LENGTH_SIZE: usize = 4;
const PADDING_LENGTH_SIZE: usize = 1;

pub struct KeyContextDirectional {
    pub cipher: Option<Box<dyn Cipher>>,
    pub cipher_mode: Option<&'static (dyn Cipher + Send + Sync)>,
    pub mac_hash: Option<&'static Hmac>,
    pub mac_key: Option<Vec<u8>>,
    pub valid: bool,
}

pub struct KeyContext {
    pub recv: Option<KeyContextDirectional>,
    pub trans: Option<KeyContextDirectional>,
    pub kex_mode: Option<KexMode>,
    pub host_signature: Option<&'static SignatureMode>,
}

pub struct PacketHandler {
    socket: TcpStream,
    write_queue: VecDeque<SSHBuffer>,

    read_buffer: Option<SSHBuffer>,

    // encrpytion
    keys: KeyContext,
    recv_seq: u32,
    trans_seq: u32,
}

impl PacketHandler {
    pub fn new(socket: TcpStream) -> Self {
        let keys = KeyContext {
            recv: Some(KeyContextDirectional {
                cipher: Some(Box::new(NoneCipher {})),
                cipher_mode: None,
                mac_hash: Some(&HMAC_NONE),
                mac_key: None,
                valid: true,
            }),
            trans: Some(KeyContextDirectional {
                cipher: Some(Box::new(NoneCipher {})),
                cipher_mode: None,
                mac_hash: Some(&HMAC_NONE),
                mac_key: None,
                valid: true,
            }),
            kex_mode: None,
            host_signature: None,
        };
        Self {
            write_queue: VecDeque::new(),
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

    pub fn get_mut_keys(&mut self) -> &mut KeyContext {
        &mut self.keys
    }

    pub fn write_packet(&mut self) {
        while !self.write_queue.is_empty() {
            let current_buffer = self.write_queue.front_mut().unwrap();
            let written = self.socket.write(&current_buffer[..]);
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
        let recv_keys = &mut self.keys.recv.as_mut().expect("recv keys should exist");
        let recv_cipher = recv_keys.cipher.as_mut().expect("No cipher initialized");
        let blocksize = recv_cipher.block_size();
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
            let len = self.socket.read(&mut readbuf[..maxlen]);
            match len {
                Ok(len) => {
                    if len == 0 {
                        panic!("remote closed");
                    } else {
                        readbuf.incr_write_pos(len);
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

    pub fn encrypt_packet(&mut self, payload: &SSHBuffer) -> Result<SSHBuffer, SSHError> {
        trace!("enter encrypt_packet");
        let trans_keys = self.keys.trans.as_mut().expect("trans keys should exist");
        let trans_cipher = trans_keys.cipher.as_mut().expect("No cipher initialized");
        let blocksize = trans_cipher.block_size();

        // add packet_length, padding_length and padding to the payload
        let payload_len = payload.len() - payload.pos();

        let include_packet_length_size = if trans_cipher.is_aead() {
            0
        } else {
            PACKET_LENGTH_SIZE
        };

        // calculates how much padding is needed, we need at least 4 bytes of padding
        let mut padding_len = blocksize
            - (payload_len + include_packet_length_size + PADDING_LENGTH_SIZE) % blocksize;

        if padding_len < 4 {
            padding_len += blocksize;
        }

        let packet_len = payload_len + padding_len + PADDING_LENGTH_SIZE;
        let mut packet = SSHBuffer::new(packet_len + PACKET_LENGTH_SIZE);

        packet.set_len(packet_len + PACKET_LENGTH_SIZE);
        // insert packet_length
        packet.put_int(packet_len as u32);
        // insert padding_length
        packet.put_byte(padding_len as u8);
        // insert payload
        packet.put_bytes(&payload[..]);

        // insert random padding
        rand::thread_rng().fill_bytes(&mut packet[..padding_len]);

        if trans_cipher.is_aead() {
            let macsize = trans_cipher.aead_mac().hashsize;
            packet.set_pos(0);

            let len = packet.len() + macsize as usize;
            packet.resize(len);
            packet.set_len(len);

            trans_cipher
                .aead_crypt_in_place(&mut packet[..], Direction::Encrypt)
                .expect("Error encrypting");
        } else {
            let mac_hash = trans_keys.mac_hash.as_ref().expect("No HMAC initialized");
            let macsize = mac_hash.hashsize;
            packet.set_pos(0);

            let len = packet.len() + macsize as usize;

            let tag = if macsize > 0 {
                let mut msg: Vec<u8> = Vec::new();
                msg.extend(self.trans_seq.to_be_bytes());
                msg.extend(&packet[..]);

                Some(compute_hmac(
                    mac_hash.mode.unwrap(),
                    &trans_keys.mac_key.as_ref().expect("No Mac Key"),
                    &msg,
                ))
            } else {
                None
            };

            trans_cipher
                .encrypt_in_place(&mut packet[..])
                .expect("Error encrpyting");

            packet.resize(len);
            packet.set_len(len);
            packet.incr_write_pos(len - macsize as usize);

            // push mac
            if let Some(tag) = tag {
                packet.put_bytes(tag.as_ref());
            }
        }
        self.trans_seq += 1;

        trace!("exit encrypt_packet");
        Ok(packet)
    }

    pub fn decrypt_packet(&mut self) -> Result<(Option<SSHBuffer>, usize), SSHError> {
        let recv_keys = self.keys.recv.as_mut().expect("recv keys should exist");
        let recv_cipher = recv_keys.cipher.as_mut().expect("No cipher initialized");
        let mac_hash = recv_keys.mac_hash.as_ref().expect("No HMAC initialized");

        let blocksize = recv_cipher.block_size();
        let macsize = mac_hash.hashsize;

        let readbuf = self.read_buffer.as_mut().unwrap();

        if recv_cipher.is_aead() {
            readbuf.set_pos(0);

            let len = readbuf.len() - readbuf.pos();
            let res = recv_cipher.aead_crypt_in_place(&mut readbuf[..len], Direction::Decrypt);
            if res.is_err() {
                panic!("Error decrypting");
            }

            readbuf.incr_pos(len);
        } else {
            readbuf.set_pos(blocksize as usize);
            let len: usize = readbuf.len() - macsize as usize - readbuf.pos();
            let res = recv_cipher.decrypt_in_place(&mut readbuf[..len]);
            if res.is_err() {
                panic!("Error decrypting");
            }

            readbuf.incr_pos(len);

            // TODO: check mac
            if macsize > 0 {
                let mut msg = Vec::new();
                msg.extend(self.recv_seq.to_be_bytes());
                msg.extend(&readbuf[0..len + blocksize as usize]);

                verify_hmac(
                    mac_hash.mode.unwrap(),
                    &recv_keys.mac_key.as_ref().expect("No mac key"),
                    &msg,
                    &readbuf[..macsize],
                )
                .expect("Verifying HMAC Failed");
            }
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
        let recv_keys = self.keys.recv.as_mut().expect("recv keys should exist");
        let recv_cipher = recv_keys.cipher.as_mut().expect("No cipher initialized");
        let mac_hash = recv_keys.mac_hash.as_ref().expect("No HMAC initialized");

        let blocksize = recv_cipher.block_size();
        let macsize = mac_hash.hashsize;

        if self.read_buffer.is_none() {
            self.read_buffer = Some(SSHBuffer::new(INIT_READBUF));
        }

        let readbuf = self.read_buffer.as_mut().unwrap();

        let maxlen = blocksize as usize - readbuf.pos();
        let read = self.socket.read(&mut readbuf[..maxlen]);

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

        if recv_cipher.is_aead() {
            let payload_len = recv_cipher.as_mut().aead_getlength(&readbuf[..]);
            if payload_len.is_err() {
                panic!("Error decrypting");
            }
            payload_length = payload_len.unwrap();
            packet_length = payload_length + 4 + macsize as u32;
        } else {
            let res = recv_cipher.decrypt_in_place(&mut readbuf[..blocksize as usize]);
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
            panic!(
                "Integrity error (bad packet size {}, blocksize {}, payload length {}",
                packet_length, blocksize, payload_length
            );
        }

        if packet_length as usize > readbuf.size() {
            readbuf.resize(packet_length as usize);
        }
        readbuf.set_len(packet_length as usize);
        readbuf.set_pos(blocksize as usize);

        Ok(())
    }

    // write queue methods
    pub fn enqueue_packet(&mut self, packet: SSHBuffer) {
        self.write_queue.push_back(packet);
    }

    pub fn is_write_queue_empty(&self) -> bool {
        self.write_queue.is_empty()
    }
}
