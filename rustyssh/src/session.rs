use std::collections::HashMap;
use std::{io::Write, net::SocketAddr};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};

const MAIN: Token = Token(0);

pub struct Session {
    socket: TcpStream,
    peer_addr: SocketAddr,
    identification: Option<String>,
}

impl Session {
    pub fn new(socket: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            socket,
            peer_addr,
            identification: None,
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
            let mut poll = Poll::new().unwrap();
            // register main socket
            println!("meow1");
            self.register_main_socket(&mut poll);
            println!("meow");

            // waits for one of the events
            poll.poll(&mut events, None).unwrap();

            for event in events.iter() {}
        }
    }

    fn register_main_socket(&mut self, poll: &mut Poll) {
        poll.registry()
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
