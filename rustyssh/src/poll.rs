use std::time::Duration;

use mio::Events;

pub struct Poll(mio::Poll);

impl Poll {
    pub fn new() -> Self {
        Self(mio::Poll::new().unwrap())
    }

    pub fn register<S>(
        &mut self,
        source: &mut S,
        token: mio::Token,
        interests: mio::Interest,
    ) -> Result<(), std::io::Error>
    where
        S: mio::event::Source + ?Sized,
    {
        let res = self.0.registry().register(source, token, interests);
        if let Err(e) = res {
            return match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    self.0
                        .registry()
                        .reregister(source, token, interests)
                        .expect(
                        "Failed to reregister after checking that the source is registered already",
                    );
                    Ok(())
                }
                _ => Err(e),
            };
        }
        Ok(())
    }

    pub fn reregister<S>(
        &mut self,
        source: &mut S,
        token: mio::Token,
        interests: mio::Interest,
    ) -> Result<(), std::io::Error>
    where
        S: mio::event::Source + ?Sized,
    {
        self.0.registry().reregister(source, token, interests)
    }

    pub fn poll(
        &mut self,
        events: &mut Events,
        timeout: Option<Duration>,
    ) -> Result<(), std::io::Error> {
        self.0.poll(events, timeout)
    }
    // pub fn reregister(&mut self,)
}
