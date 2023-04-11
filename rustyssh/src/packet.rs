use std::collections::VecDeque;

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

    pub fn write_packet(&mut self, session: &Session) {}

    pub fn read_packet(&mut self, session: &Session) {}

    pub fn process_packet(&mut self, payload: &mut SSHBuffer) {}

    // write queue methods
    pub fn enqueue_packet(&mut self, packet: SSHBuffer) {
        self.write_queue.push_back(packet);
    }

    pub fn is_write_queue_empty(&self) -> bool {
        self.write_queue.is_empty()
    }
}
