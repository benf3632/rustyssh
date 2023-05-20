pub struct AuthState {
    pub authenticated: bool,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState {
            authenticated: false,
        }
    }
}
