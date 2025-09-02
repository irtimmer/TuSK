use std::time::SystemTime;

use opensk::api::clock::Clock;

use crate::env::TuskEnv;

/// Implements the `Clock` trait for `TuskEnv`.
///
/// This implementation uses a simple millisecond-based timestamp system, where a timer
/// is represented as a `u64` timestamp marking a future point in time.
///
/// The `now()` function is used as the source of the current time in milliseconds.
impl Clock for TuskEnv {
    type Timer = u64;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        now() + milliseconds as u64
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        now() >= *timer
    }
}

/// Returns the current time in milliseconds since the UNIX epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}
