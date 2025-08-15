use std::time::SystemTime;

use opensk::api::clock::Clock;

use crate::env::TuskEnv;

impl Clock for TuskEnv {
    type Timer = u64;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        now() + milliseconds as u64
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        now() >= *timer
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}
