use std::{
    collections::VecDeque,
    io::{ErrorKind, Write},
};

use mio::net::TcpStream;

use crate::{session::Session, sshbuffer::SSHBuffer};

pub struct PacketHandler {
    write_queue: VecDeque<SSHBuffer>,
}

impl PacketHandler {
    pub fn new() -> Self {
        Self {
            write_queue: VecDeque::new(),
        }
    }

    pub fn write_packet(&mut self, socket: &mut TcpStream) {
        while !self.write_queue.is_empty() {
            let current_buffer = self.write_queue.front_mut().unwrap();
            current_buffer.set_pos(0);
            let written = socket.write(current_buffer.get_slice());
            match written {
                Ok(written) => {
                    if written == 0 {
                        panic!("Remote closed from peer");
                    } else if written != current_buffer.len() - current_buffer.pos() {
                        current_buffer.incr_pos(written);
                        return;
                    } else {
                        self.write_queue.pop_front();
                    }
                }
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    return;
                }
                Err(_) => {
                    panic!("Failed to write packet");
                }
            };
        }
    }

    pub fn read_packet(&mut self, session: &mut Session) {
        unimplemented!();
    }

    pub fn process_packet(&mut self, payload: &mut SSHBuffer) {
        unimplemented!();
    }

    // write queue methods
    pub fn enqueue_packet(&mut self, packet: SSHBuffer) {
        self.write_queue.push_back(packet);
    }

    pub fn is_write_queue_empty(&self) -> bool {
        self.write_queue.is_empty()
    }
}
