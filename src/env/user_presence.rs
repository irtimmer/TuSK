use std::thread;
use std::io;

use opensk::api::clock::Clock;
use opensk::api::connection::{HidConnection, RecvStatus};
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceWaitResult};
use opensk::ctap::status_code::Ctap2StatusCode;

use pinentry::{ConfirmationDialog, Error};

use crate::env::TuskEnv;

#[derive(Default)]
pub struct PinentryPresence {
    handle: Option<thread::JoinHandle<Result<bool, pinentry::Error>>>,
}

impl UserPresence for TuskEnv {
    fn check_init(&mut self) {}

    fn wait_with_timeout(&mut self, packet: &mut [u8; 64], timeout_ms: usize) -> UserPresenceWaitResult {
        let timer = self.make_timer(timeout_ms);

        loop {
            let handle = self.presence.handle.get_or_insert_with(|| thread::spawn(ask_confirmation));

            if handle.is_finished() {
                let handle = self.presence.handle.take().unwrap();
                return match handle.join() {
                    Ok(Ok(true)) => Ok((Ok(()), RecvStatus::Timeout)),
                    Ok(Ok(false)) => Ok((Err(UserPresenceError::Declined), RecvStatus::Timeout)),
                    Ok(Err(_)) | Err(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE),
                };
            }

            match self.hid.recv(packet, 100) {
                Ok(RecvStatus::Received(e)) => return Ok((Ok(()), RecvStatus::Received(e))),
                Err(e) => return Err(e),
                _ => ()
            }

            if self.is_elapsed(&timer) {
                return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
            }
        }
    }

    fn check_complete(&mut self) {}
}

/// Asks for confirmation using the `pinentry` tool.
///
/// This function displays a confirmation dialog to the user and returns
/// `Ok(true)` if the user confirms, `Ok(false)` if the user cancels, and
/// `Err` if an error occurs or `pinentry` is not available.
fn ask_confirmation() -> Result<bool, pinentry::Error> {
    if let Some(mut dialog) = ConfirmationDialog::with_default_binary() {
        dialog
            .with_title("TuSK")
            .with_ok("Yes")
            .with_not_ok("No")
            .confirm("Do you want to use TuSK as security key?")
    } else {
        Err(Error::Io(io::Error::new(std::io::ErrorKind::NotFound, "pinentry binary not found")))
    }
}
