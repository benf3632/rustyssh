use std::net::SocketAddr;

use rustyssh::session::Session;

pub fn handle_connection(mut socket: mio::net::TcpStream, addr: SocketAddr) {
    let mut sess = Session::new(socket, addr);
    sess.send_session_identification();
    sess.session_loop();
}
