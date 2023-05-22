use crate::{crypto::signature::SIGNATURES, msg::SSHMsg, session::SessionHandler};
use log::trace;

pub const SUPPORTED_SIGNATURES: &[&'static str] = &["ssh-rsa"];

impl SessionHandler {
    pub fn auth_publickey(&mut self, valid_user: bool) {
        trace!("enter auth_publickey");
        let payload = self.session.payload.as_mut().expect("payload should exist");

        let verify = payload.get_bool();

        let public_key_algo =
            String::from_utf8(payload.get_string().0).expect("invalid public key algo name");

        // check if server supports this algo
        if !SUPPORTED_SIGNATURES
            .iter()
            .any(|e| *e == public_key_algo.as_str())
        {
            self.send_msg_userauth_failure(false);
            trace!("exit auth_publickey");
            return;
        }

        let (public_key_blob, _) = payload.get_string();

        if !verify {
            self.send_msg_userauth_pk_ok(public_key_algo, public_key_blob);
            trace!("exit auth_publickey");
            return;
        }

        // TODO: implement verifying signature

        trace!("exit auth_publickey");
    }

    pub fn send_msg_userauth_pk_ok(&mut self, public_key_algo: String, public_key_blob: Vec<u8>) {
        trace!("enter send_msg_userauth_pk_ok");

        let write_payload = &mut self.session.write_payload;

        write_payload.set_len(0);
        write_payload.set_pos(0);

        write_payload.put_byte(SSHMsg::UserauthPKOk.into());
        write_payload.put_string(public_key_algo.as_bytes(), public_key_algo.len());
        write_payload.put_string(&public_key_blob, public_key_blob.len());

        write_payload.set_pos(0);

        let mut packet = self
            .packet_handler
            .encrypt_packet(write_payload)
            .expect("Falied to encrypt packet");

        packet.set_pos(0);
        self.packet_handler.enqueue_packet(packet);

        trace!("exit send_msg_userauth_pk_ok");
    }
}
