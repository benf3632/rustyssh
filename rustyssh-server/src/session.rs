use std::net::SocketAddr;

use rustyssh::session::{send_identification, Session};

pub fn handle_connection(mut socket: mio::net::TcpStream, addr: SocketAddr) {
    let mut sess = Session::new(socket, addr);
    send_identification(&mut sess);
    sess.session_loop();
}
