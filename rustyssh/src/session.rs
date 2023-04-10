use std::collections::HashMap;
use std::{io::Write, net::SocketAddr};

use mio::net::TcpStream;
use mio::{Events, Interest, Token};

use crate::poll::Poll;

const MAIN: Token = Token(0);

pub struct Session {
    socket: TcpStream,
    peer_addr: SocketAddr,
    identification: Option<String>,
    poll: Poll,
}

impl Session {
    pub fn new(socket: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            socket,
            peer_addr,
            identification: None,
            poll: Poll::new(),
        }
    }

    pub fn socket(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    pub fn session_loop(&mut self) {
        let mut events = Events::with_capacity(128);

        // register all sockets
        let write_sockets = HashMap::<usize, TcpStream>::new();
        let read_sockets = HashMap::<usize, TcpStream>::new();

        loop {
            // register main socket
            self.register_main_socket();

            // waits for one of the events
            self.poll.poll(&mut events, None).unwrap();

            for event in events.iter() {}
        }
    }

    fn register_main_socket(&mut self) {
        self.poll
            .register(
                &mut self.socket,
                MAIN,
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("Failed to register main socket");
    }
}

pub fn send_identification(sess: &mut Session) {
    let ident = format!("SSH-2.0-rustyssh{}\r\n", env!("CARGO_PKG_VERSION"));
    sess.socket.write_all(ident.as_bytes()).unwrap();
}
