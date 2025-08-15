use std::fs::File;

use opensk::{Ctap, Transport};
use opensk::ctap::status_code::CtapResult;
use opensk::api::connection::{HidConnection, UsbEndpoint, RecvStatus};
use opensk::env::Env;

use crate::env::TuskEnv;
use crate::hid::FidoHid;

mod hid;
mod env;

fn main() {
    if let Err(e) = run_fido_hid() {
        eprintln!("Error: {:?}", e);
    }
}

fn run_fido_hid() -> CtapResult<()> {
    let device = FidoHid::<File>::new().expect("Failed to create FIDO HID device");
    println!("Virtual FIDO2 HID device created. Waiting for host...");

    let env = TuskEnv::new(device);
    let mut ctap = Ctap::new(env);
    loop {
        let mut packet = [0; 64];
        match ctap.env().hid_connection().recv(&mut packet, 100)? {
            RecvStatus::Timeout => continue,
            RecvStatus::Received(endpoint) => assert_eq!(endpoint, UsbEndpoint::MainHid),
        }

        for packet in ctap.process_hid_packet(&packet, Transport::MainHid) {
            ctap.env().hid_connection().send(&packet, UsbEndpoint::MainHid)?;
        }
    }
}
