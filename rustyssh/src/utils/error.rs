pub enum SSHError {
    Failure,
    Io(std::io::Error),
}
