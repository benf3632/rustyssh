use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::SocketAddr;

use mio::event::Source;
use mio::net::TcpStream;
use mio::{Events, Interest, Token};

use crate::algo::{Hash, Kex};
use crate::crypto::cipher::none::NONE_CIPHER_HASH;
use crate::crypto::cipher::{Cipher, NONE_CIPHER};
use crate::msg::SSHMsg;
use crate::packet::PacketHandler;
use crate::server::session::SERVER_PACKET_TYPES;
use crate::signkey::SignatureType;
use crate::sshbuffer::SSHBuffer;
use crate::utils::poll::Poll;

const MAIN: Token = Token(0);

const TRANS_MAX_PAYLOAD_LEN: usize = 16384;

pub struct KeyContextDirectional {
    pub cipher: Cipher,
    pub mac_hash: Hash,
    pub mac_key: Vec<u8>,
    pub valid: bool,
}

pub struct KeyContext {
    pub recv: KeyContextDirectional,
    pub trans: KeyContextDirectional,
    pub algo_kex: Option<Kex>,
    pub algo_signature: SignatureType,
}

pub struct Session {
    pub socket: TcpStream,
    pub is_server: bool,
    pub peer_addr: SocketAddr,
    pub identification: Option<String>,
    pub local_ident: String,

    pub write_payload: SSHBuffer,
    pub readbuf: Option<SSHBuffer>,
    pub payload: Option<SSHBuffer>,
    pub payload_beginning: usize,

    pub require_next: SSHMsg,
    pub last_packet: SSHMsg,
    pub ignore_next: bool,

    pub transseq: u32,
    pub recvseq: u32,

    pub keys: Option<KeyContext>,
    pub newkeys: Option<KeyContext>,
    // TODO: add kexstate, session_id
}

pub struct SessionHandler<'a> {
    poll: Poll,
    session: Session,
    packet_handler: PacketHandler<'a>,
}

impl<'a> SessionHandler<'a> {
    pub fn new(socket: TcpStream, peer_addr: SocketAddr, is_server: bool) -> Self {
        let keys = KeyContext {
            recv: KeyContextDirectional {
                cipher: Cipher {
                    keysize: NONE_CIPHER.keysize,
                    blocksize: NONE_CIPHER.blocksize,
                    crypt_mode: (NONE_CIPHER.cipher_init)(),
                },
                mac_hash: NONE_CIPHER_HASH,
                mac_key: Vec::new(),
                valid: true,
            },
            trans: KeyContextDirectional {
                cipher: Cipher {
                    keysize: NONE_CIPHER.keysize,
                    blocksize: NONE_CIPHER.blocksize,
                    crypt_mode: (NONE_CIPHER.cipher_init)(),
                },
                mac_hash: NONE_CIPHER_HASH,
                mac_key: Vec::new(),
                valid: true,
            },
            algo_kex: None,
            algo_signature: SignatureType::None,
        };
        Self {
            session: Session {
                socket,
                peer_addr,
                is_server,
                identification: None,
                write_payload: SSHBuffer::new(TRANS_MAX_PAYLOAD_LEN),
                readbuf: None,
                payload: None,
                payload_beginning: 0,
                require_next: SSHMsg::KEXINIT,
                ignore_next: false,
                last_packet: SSHMsg::None,
                transseq: 0,
                recvseq: 0,
                local_ident: format!("SSH-2.0-rustyssh_{}", env!("CARGO_PKG_VERSION")),
                keys: Some(keys),
                newkeys: None,
            },
            poll: Poll::new(),
            packet_handler: PacketHandler::new(&SERVER_PACKET_TYPES),
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        &mut self.session.socket
    }

    pub fn session_loop(&mut self) {
        let mut events = Events::with_capacity(128);

        loop {
            self.register_main_socket(!self.packet_handler.is_write_queue_empty());

            // waits for one of the events
            self.poll.poll(&mut events, None).expect("Failed to poll");

            for event in events.iter() {
                match event.token() {
                    MAIN => {
                        if event.is_readable() {
                            if self.session.identification.is_none() {
                                self.read_session_identification();
                            } else {
                                self.packet_handler.read_packet(&mut self.session);
                            }

                            if self.session.payload.is_some() {
                                self.packet_handler.process_packet(&mut self.session)
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // TODO: process write packet queue
                if !self.packet_handler.is_write_queue_empty() {
                    self.packet_handler.write_packet(&mut self.session.socket);
                }
            }
        }
    }

    fn register_main_socket(&mut self, writable: bool) {
        let mut interest = Interest::READABLE;
        if writable {
            interest |= Interest::WRITABLE;
        }
        self.poll
            .register(&mut self.session.socket, MAIN, interest)
            .expect("Failed to register main socket");
    }

    fn register_readable_stream<S>(&mut self, stream: &mut S, token: Token)
    where
        S: Source + ?Sized,
    {
        self.poll
            .register(stream, token, Interest::READABLE)
            .expect("Failed to register stream");
    }

    fn register_writeable_stream<S>(&mut self, stream: &mut S, token: Token)
    where
        S: Source + ?Sized,
    {
        self.poll
            .register(stream, token, Interest::WRITABLE)
            .expect("Failed to register stream");
    }

    fn read_session_identification(&mut self) {
        println!("vered");

        let ident = self.read_identln().expect("expected line");

        if !ident.starts_with("SSH-2.0") {
            panic!("invalid identification string");
        }

        self.session.identification = Some(ident);
        print!(
            "Ident string: {}",
            self.session.identification.as_ref().unwrap().as_str()
        );
    }

    fn read_identln(&mut self) -> Result<String, std::io::Error> {
        let buf_reader = BufReader::with_capacity(255, &self.session.socket);

        let mut handle = buf_reader.take(256);
        let mut line = String::new();

        let res = handle.read_line(&mut line);
        if res.is_err() {
            return Err(res.err().unwrap());
        }

        let len = res.unwrap();
        if len == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "got eof while reading identification string",
            ));
        }

        Ok(line)
    }

    pub fn send_session_identification(&mut self) {
        let ident = format!("{}\r\n", self.session.local_ident);
        let mut buf = SSHBuffer::new(ident.len());
        buf.put_bytes(ident.as_bytes());
        self.packet_handler.enqueue_packet(buf);
    }
}
