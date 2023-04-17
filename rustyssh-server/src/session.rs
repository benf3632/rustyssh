use std::net::SocketAddr;

use rustyssh::session::SessionHandler;

pub fn handle_connection(socket: mio::net::TcpStream, addr: SocketAddr) {
    let mut sess = SessionHandler::new(socket, addr, true);
    sess.send_session_identification();
    sess.session_loop();
}
