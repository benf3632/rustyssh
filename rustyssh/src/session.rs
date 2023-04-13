use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::SocketAddr;

use mio::event::Source;
use mio::net::TcpStream;
use mio::{Events, Interest, Token};

use crate::packet::PacketHandler;
use crate::sshbuffer::SSHBuffer;
use crate::utils::poll::Poll;

const MAIN: Token = Token(0);

pub struct Session {
    pub socket: TcpStream,
    pub peer_addr: SocketAddr,
    pub identification: Option<String>,
}

pub struct SessionHandler {
    poll: Poll,
    session: Session,
    packet_handler: PacketHandler,
}

impl SessionHandler {
    pub fn new(socket: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            session: Session {
                socket,
                peer_addr,
                identification: None,
            },
            poll: Poll::new(),
            packet_handler: PacketHandler::new(),
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
                                // TODO: read packet
                                self.packet_handler.read_packet(&mut self.session);
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
        let ident = format!("SSH-2.0-rustyssh_{}\r\n", env!("CARGO_PKG_VERSION"));
        let mut buf = SSHBuffer::new(ident.len());
        buf.put_bytes(ident.as_bytes());
        self.packet_handler.enqueue_packet(buf);
    }
}
