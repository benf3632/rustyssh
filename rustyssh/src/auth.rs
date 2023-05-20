use crate::namelist::Name;
use pwd::Passwd;

pub struct AuthState {
    pub authenticated: bool,
    pub acceptable_methods: Option<Vec<Name>>,
    pub username: Option<String>,
    pub pw: Option<Passwd>,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState {
            authenticated: false,
            acceptable_methods: None,
            username: None,
            pw: None,
        }
    }
}

pub const PASSWORD_METHOD: Name = Name("password");
pub const PUBLICKEY_METHOD: Name = Name("publickey");
pub const NONE_METHOD: Name = Name("none");
