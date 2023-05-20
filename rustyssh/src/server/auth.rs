use log::warn;
use once_cell::sync::Lazy;
use pwd::Passwd;

use crate::{
    auth::{NONE_METHOD, PASSWORD_METHOD, PUBLICKEY_METHOD},
    msg::SSHMsg,
    namelist::Name,
    session::SessionHandler,
};

pub const ACCEPTABLE_METHODS: &[Name] = &[PUBLICKEY_METHOD, PASSWORD_METHOD];

impl SessionHandler {
    pub fn recv_msg_userauth_request(&mut self) {
        let payload = self.session.payload.as_mut().expect("payload should exist");

        let (username, _) = payload.get_string();
        let (service_name, _) = payload.get_string();
        let (method_name, _) = payload.get_string();

        let username = std::str::from_utf8(&username).expect("invalid user name string");
        let service_name = std::str::from_utf8(&service_name).expect("invalid service name string");
        let method_name = std::str::from_utf8(&method_name).expect("invalid method name string");

        if self.session.auth_state.authenticated {
            warn!("exit recv_msg_userauth_request: already authenticated");
            return;
        }

        if service_name != "ssh-connection" {
            panic!("invalid service name");
        }

        let valid_user = self.check_username(username);

        match method_name {
            "none" => self.send_msg_userauth_failure(false),
            "publickey" => todo!("implement publickey auth"),
            "password" => todo!("implement password auth"),
            _ => self.send_msg_userauth_failure(false),
        }
    }
    pub fn send_msg_userauth_success(&mut self) {
        let write_payload = &mut self.session.write_payload;

        write_payload.set_pos(0);
        write_payload.set_len(0);

        write_payload.put_byte(SSHMsg::UserauthSuccess.into());

        write_payload.set_pos(0);
        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("failed to encrypt packet");

        packet.set_pos(0);
        self.packet_handler.enqueue_packet(packet);
    }

    pub fn send_msg_userauth_failure(&mut self, partial: bool) {
        let write_payload = &mut self.session.write_payload;

        write_payload.set_len(0);
        write_payload.set_pos(0);

        write_payload.put_byte(SSHMsg::UserauthFailure.into());
        write_payload.put_namelist(
            self.session
                .auth_state
                .acceptable_methods
                .as_ref()
                .expect("acceptable methods should exist"),
        );
        write_payload.put_bool(partial);

        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("failed to encrypt packet");
        packet.set_pos(0);

        self.packet_handler.enqueue_packet(packet);
    }

    // the method checks if the user exists in the passwd file
    // and populates the auth state with passwd struct
    pub fn check_username(&mut self, username: &str) -> bool {
        if self.session.auth_state.username.is_none() {
            self.fill_passwd(username);
            self.session.auth_state.username = Some(String::from(username));
        } else {
            if self.session.auth_state.username.as_ref().unwrap() != username {
                panic!("client is trying multiple usernames");
            }
        }

        if self.session.auth_state.pw.is_none() {
            return false;
        }

        // TODO: add checking for no root login

        true
    }

    pub fn fill_passwd(&mut self, username: &str) {
        self.session.auth_state.pw = Passwd::from_name(username).expect("invalid username");
    }
}
