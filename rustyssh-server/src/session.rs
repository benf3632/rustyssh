use std::{net::SocketAddr, sync::Arc};

use rustyssh::{crypto::signature::HostKeys, session::SessionHandler};

pub fn handle_connection(socket: mio::net::TcpStream, addr: SocketAddr, hostkeys: Arc<HostKeys>) {
    let mut sess = SessionHandler::new(socket, hostkeys, addr, true);
    sess.send_session_identification();
    sess.session_loop();
}
