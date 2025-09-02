use opensk::api::connection::RecvStatus;
use opensk::api::user_presence::{UserPresence, UserPresenceWaitResult};

use crate::env::TuskEnv;

/// Implementation of the `UserPresence` trait for `TuskEnv`.
///
/// The current implementation fakes user presence checks by immediately returning
/// a timeout status without waiting for any real user interaction.
impl UserPresence for TuskEnv {
    fn check_init(&mut self) {}

    fn wait_with_timeout(&mut self, _packet: &mut [u8; 64], _timeout_ms: usize) -> UserPresenceWaitResult {
        Ok((Ok(()), RecvStatus::Timeout))
    }

    fn check_complete(&mut self) {}
}
