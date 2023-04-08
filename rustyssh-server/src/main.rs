use mio::{net::TcpStream, Events, Interest, Poll, Token};
use std::net;
use std::{io::Write, net::SocketAddr};

use rustyssh::sshbuffer::SSHBuffer;

const MAIN: Token = Token(0);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let addr = "127.0.0.1:7878".parse()?;
    let listener = net::TcpListener::bind("127.0.0.1:7878")?;

    for socket in listener.incoming() {
        let socket = socket.unwrap();
        let addr = socket.peer_addr().unwrap();

        socket.set_nonblocking(true).unwrap();

        let socket = TcpStream::from_std(socket);
        println!("Accepted client");
        std::thread::spawn(move || handle_connection(socket, addr));
    }
    Ok(())
}

fn handle_connection(mut socket: TcpStream, addr: SocketAddr) {
    send_identifcation(&mut socket);

    let mut poll = Poll::new().unwrap();

    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut socket, MAIN, Interest::READABLE | Interest::WRITABLE)
        .unwrap();

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {}
    }
}

fn send_identifcation(socket: &mut TcpStream) {
    let ident = format!("SSH-2.0-rustyssh{}\r\n", env!("CARGO_PKG_VERSION"));
    socket.write_all(ident.as_bytes()).unwrap();
}
