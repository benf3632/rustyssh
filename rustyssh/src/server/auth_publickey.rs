use crate::{
    crypto::signature::{self, SIGNATURES},
    msg::SSHMsg,
    session::SessionHandler,
    sshbuffer::SSHBuffer,
};
use log::{info, trace, warn};

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

        // TODO: read authorized keys, and check if the public key is in there

        if !verify {
            self.send_msg_userauth_pk_ok(public_key_algo, public_key_blob);
            trace!("exit auth_publickey");
            return;
        }

        // put public key in ssh buffer
        let mut unparsed_public_key = SSHBuffer::new(public_key_blob.len());
        unparsed_public_key.put_bytes(&public_key_blob);
        unparsed_public_key.set_pos(0);

        let public_key = signature::parse_public_key_blob(&mut unparsed_public_key);

        if public_key.is_err() {
            warn!("Invalid public key supplied, auth failed");
            self.send_msg_userauth_failure(false);
            return;
        }

        let public_key = public_key.unwrap();

        let (signature, _) = payload.get_string();

        let session_id = self
            .session
            .session_id
            .as_ref()
            .expect("session id should exist");

        let mut signature_to_verify =
            SSHBuffer::new(session_id.len() + payload.len() - signature.len());

        payload.set_pos(self.session.payload_beginning);

        signature_to_verify.put_string(&session_id, session_id.len());

        signature_to_verify.put_bytes(&payload[..payload.len() - signature.len()]);

        if let Ok(_) = public_key.verify(&signature_to_verify[0..], &signature) {
            info!("User logged in with a correct public_key");
            self.send_msg_userauth_success();
        } else {
            info!("Invalid public key signature");
            self.send_msg_userauth_failure(false);
        }

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
