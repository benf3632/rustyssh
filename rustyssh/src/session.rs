use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::{io::Write, net::SocketAddr};

use mio::net::TcpStream;
use mio::{Events, Interest, Token};

use crate::packet::PacketHandler;
use crate::sshbuffer::SSHBuffer;
use crate::utils::poll::Poll;

const MAIN: Token = Token(0);

pub struct Session {
    socket: TcpStream,
    peer_addr: SocketAddr,
    identification: Option<String>,
    poll: Poll,
    packet_handler: PacketHandler,
}

impl Session {
    pub fn new(socket: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            socket,
            peer_addr,
            identification: None,
            poll: Poll::new(),
            packet_handler: PacketHandler::new(),
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    pub fn session_loop(&mut self) {
        let mut events = Events::with_capacity(128);

        loop {
            self.register_main_socket();

            // waits for one of the events
            self.poll.poll(&mut events, None).expect("Failed to poll");

            for event in events.iter() {
                match event.token() {
                    MAIN => {
                        if event.is_readable() {
                            if self.identification.is_none() {
                                self.read_session_identification();
                            } else {
                                // TODO: read packet
                                unimplemented!();
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // TODO: process write packet queue
            }
        }
    }

    fn register_main_socket(&mut self) {
        self.poll
            .register(&mut self.socket, MAIN, Interest::READABLE)
            .expect("Failed to register main socket");
    }

    fn read_session_identification(&mut self) {
        println!("vered");

        let ident = self.read_identln().expect("expected line");

        if !ident.starts_with("SSH-2.0") {
            panic!("invalid identification string");
        }

        self.identification = Some(ident);
        print!(
            "Ident string: {}",
            self.identification.as_ref().unwrap().as_str()
        );
    }

    fn read_identln(&mut self) -> Result<String, std::io::Error> {
        let buf_reader = BufReader::with_capacity(255, &self.socket);

        let mut handle = buf_reader.take(255);
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
        buf.putbytes(ident.as_bytes());
        self.packet_handler.enqueue_packet(buf);
    }
}
