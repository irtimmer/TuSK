use opensk::api::connection::RecvStatus;
use opensk::api::user_presence::{UserPresence, UserPresenceWaitResult};

use crate::env::TuskEnv;

impl UserPresence for TuskEnv {
    fn check_init(&mut self) {}

    fn wait_with_timeout(&mut self, _packet: &mut [u8; 64], _timeout_ms: usize) -> UserPresenceWaitResult {
        Ok((Ok(()), RecvStatus::Timeout))
    }

    fn check_complete(&mut self) {}
}
