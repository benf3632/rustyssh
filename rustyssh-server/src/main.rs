use std::net;

mod session;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = net::TcpListener::bind("127.0.0.1:7878")?;

    for socket in listener.incoming() {
        let socket = socket.unwrap();
        let addr = socket.peer_addr().unwrap();

        socket.set_nonblocking(true).unwrap();

        let socket = mio::net::TcpStream::from_std(socket);
        println!("Accepted client");
        std::thread::spawn(move || session::handle_connection(socket, addr));
    }
    Ok(())
}
