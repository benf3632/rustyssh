use crate::{msg::SSHMsg, session::SessionHandler};
use log::{debug, trace};

impl SessionHandler {
    pub fn recv_msg_service_request(&mut self) {
        let payload = self.session.payload.as_mut().expect("payload should exist");
        let (service_name, _) = payload.get_string();
        let service_name = std::str::from_utf8(&service_name).expect("invalid string");

        match service_name {
            "ssh-userauth" if !self.session.auth_state.authenticated => {
                self.send_msg_service_accept(service_name)
            }
            "ssh-connection" if self.session.auth_state.authenticated => {
                self.send_msg_service_accept(service_name)
            }
            _ => todo!("send msg disconnect"),
        }
    }

    pub fn send_msg_service_accept(&mut self, service_name: &str) {
        trace!("enter send_msg_service_accept");
        let write_payload = &mut self.session.write_payload;
        // reset write payload
        write_payload.set_len(0);
        write_payload.set_pos(0);

        write_payload.put_byte(SSHMsg::ServiceAccept.into());
        write_payload.put_string(service_name.as_bytes(), service_name.len());

        write_payload.set_pos(0);
        debug!("payload: {:?}", &write_payload[0..]);
        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("Encryption failed");

        packet.set_pos(0);
        self.packet_handler.enqueue_packet(packet);

        trace!("exit send_msg_service_accpet");
    }
}
