use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use mio::event::Source;
use mio::net::TcpStream;
use mio::{Events, Interest, Token};

use crate::auth::AuthState;
use crate::crypto::signature::HostKeys;
use crate::kex::KexState;
use crate::msg::SSHMsg;
use crate::packet::{KeyContext, PacketHandler};
use crate::server::auth::ACCEPTABLE_METHODS;
use crate::server::session::SERVER_PACKET_HANDLERS;
use crate::sshbuffer::SSHBuffer;
use crate::utils::poll::Poll;

const MAIN: Token = Token(0);

const TRANS_MAX_PAYLOAD_LEN: usize = 16384;

pub struct Session {
    pub is_server: bool,
    pub peer_addr: SocketAddr,
    pub identification: Option<String>,
    pub local_ident: String,

    pub write_payload: SSHBuffer,
    pub payload: Option<SSHBuffer>,
    pub payload_beginning: usize,

    pub require_next: SSHMsg,
    pub last_packet: SSHMsg,
    pub ignore_next: bool,

    pub hostkeys: Arc<HostKeys>,
    pub newkeys: Option<KeyContext>,
    pub kex_state: KexState,
    pub exchange_hash: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
    pub secret_key: Option<Vec<u8>>,
    pub local_kex_init_message: Option<SSHBuffer>,
    pub kex_hash_buffer: Option<SSHBuffer>,

    pub auth_state: AuthState,
}

pub struct SessionHandler {
    poll: Poll,
    pub session: Session,
    pub packet_handler: PacketHandler,
}

impl SessionHandler {
    pub fn new(
        socket: TcpStream,
        hostkeys: Arc<HostKeys>,
        peer_addr: SocketAddr,
        is_server: bool,
    ) -> Self {
        let mut auth_state = AuthState::default();
        if is_server {
            auth_state.acceptable_methods = Some(ACCEPTABLE_METHODS.clone().to_vec());
        }
        Self {
            session: Session {
                peer_addr,
                is_server,
                identification: None,
                write_payload: SSHBuffer::new(TRANS_MAX_PAYLOAD_LEN),
                payload: None,
                payload_beginning: 0,
                require_next: SSHMsg::KexInit,
                ignore_next: false,
                last_packet: SSHMsg::None,
                kex_state: KexState::default(),
                hostkeys,
                secret_key: None,
                exchange_hash: None,
                session_id: None,
                local_kex_init_message: None,
                kex_hash_buffer: None,
                local_ident: format!("SSH-2.0-rustyssh_{}", env!("CARGO_PKG_VERSION")),
                newkeys: None,
                auth_state,
            },
            poll: Poll::new(),
            packet_handler: PacketHandler::new(socket),
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        self.packet_handler.socket()
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
                                if let Ok((payload, payload_beginning)) =
                                    self.packet_handler.read_packet()
                                {
                                    self.session.payload = payload;
                                    self.session.payload_beginning = payload_beginning;
                                }
                            }

                            if self.session.payload.is_some() {
                                self.process_payload();
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // TODO: process write packet queue
                if !self.packet_handler.is_write_queue_empty() {
                    self.packet_handler.write_packet();
                }
            }
        }
    }

    pub fn process_payload(&mut self) {
        let msg_type = self.session.payload.as_mut().unwrap().get_byte();

        trace!(
            "process_packet: packet type = {:?}, len = {}",
            msg_type,
            self.session.payload.as_mut().unwrap().len()
        );

        if !self.session.auth_state.authenticated && msg_type > 60 {
            panic!("Received authenticated packet while not authenticated yet");
        }

        let msg_type: SSHMsg = msg_type.into();

        let mut cleanup = || {
            self.session.last_packet = msg_type;
            self.session.payload.take();
        };

        match msg_type {
            SSHMsg::Ignore => {
                cleanup();
                return;
            }
            SSHMsg::Unimplemented => {
                trace!("SSH_MSG_UNIMPLEMENTED");
                cleanup();
                return;
            }
            SSHMsg::Disconnect => {
                // TODO: Cleanup
                panic!("Disconnect received");
            }

            _ => {}
        }

        if self.session.require_next != SSHMsg::None {
            if self.session.require_next == msg_type {
                trace!("got expected packet {:?} during kexinit", msg_type);
            } else {
                if msg_type != SSHMsg::KexInit {
                    warn!("unknown allowed packet during kexinit");
                    // handle unimplemented
                    cleanup();
                    return;
                } else {
                    error!("disallowed packet during kexinit");
                    panic!(
                        "Unexpected packet type {:?}, expected {:?}",
                        msg_type, self.session.require_next
                    );
                }
            }
        }

        if self.session.ignore_next {
            info!("Ignoring packet, type = {:?}", msg_type);
            self.session.ignore_next = false;
            cleanup();
            return;
        }

        if self.session.require_next != SSHMsg::None && self.session.require_next == msg_type {
            self.session.require_next = SSHMsg::None;
        }

        // TODO: check for auth state when implemented
        if self.session.is_server {
            let packet_handler = SERVER_PACKET_HANDLERS
                .get(&msg_type)
                .expect("unimplemented handler");
            packet_handler(self);
            return;
        }

        // TODO: recv unimplemented

        unimplemented!();
    }

    fn register_main_socket(&mut self, writable: bool) {
        let mut interest = Interest::READABLE;
        if writable {
            interest |= Interest::WRITABLE;
        }
        self.poll
            .register(self.packet_handler.socket(), MAIN, interest)
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
        trace!("vered");

        let mut ident = self.read_identln().expect("expected line");

        if !ident.starts_with("SSH-2.0") {
            panic!("invalid identification string");
        }

        // remove CRLF
        ident = ident.replace("\n", "").replace("\r", "");

        self.session.identification = Some(ident);
        debug!(
            "Ident string: {}",
            self.session.identification.as_ref().unwrap().as_str()
        );
    }

    fn read_identln(&mut self) -> Result<String, std::io::Error> {
        let buf_reader = BufReader::with_capacity(255, self.socket());

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
        buf.set_pos(0);
        self.packet_handler.enqueue_packet(buf);
    }
}
