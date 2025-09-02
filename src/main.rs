//! Tusk: A virtual FIDO2 authenticator backed by a TPM.
//!
//! This application creates a virtual FIDO2/CTAP HID device that allows a host
//! system to perform authentication gestures using a Trusted Platform Module (TPM)
//! as the cryptographic backend. It effectively turns a computer with a TPM into a
//! roaming authenticator (like a YubiKey or a Titan Security Key).
//!
//! # Execution Flow
//!
//! 1.  **Initialization**: The `main` function starts by initializing logging and
//!     setting up necessary application directories using the XDG Base Directory
//!     Specification via the `init_data` function.
//!
//! 2.  **Configuration**: It reads configuration from a file (e.g., `~/.config/tusk/tusk.cfg`)
//!     and environment variables (prefixed with `TUSK_`). The primary configuration is `tcti`,
//!     which specifies the TPM Command Transmission Interface (e.g., "device:/dev/tpmrm0").
//!     This is handled by `read_config`.
//!
//! 3.  **TPM Setup**: The TPM is initialized using the provided `tcti` configuration string.
//!
//! 4.  **Virtual Device Creation**: A virtual FIDO HID device is created using the `uhid`
//!     kernel module. This device appears to the host operating system as a physical
//!     USB security key.
//!
//! 5.  **Main Loop**: The `run_fido_hid` function enters an infinite loop to service requests
//!     from the host. It waits for HID packets, processes them using the `opensk` CTAP
//!     library, and sends response packets back. The `TuskEnv` struct provides the
//!     necessary environment (TPM access, storage) for the `opensk` library to function.
//!
//! # Modules
//!
//! - `hid`: Manages the creation and interaction with the virtual FIDO HID device.
//! - `env`: Implements the `opensk::env::Env` trait, bridging the `opensk` library with
//!   the TPM backend and application storage.
//! - `tpm`: Contains the logic for initializing and interacting with the TPM.

extern crate alloc;

use std::io;
use std::fs::File;
use std::path::PathBuf;

use config::Config;

use opensk::{Ctap, Transport};
use opensk::ctap::status_code::CtapResult;
use opensk::api::connection::{HidConnection, UsbEndpoint, RecvStatus};
use opensk::env::Env;

use serde::Deserialize;

use xdg::BaseDirectories;

use crate::env::TuskEnv;
use crate::hid::FidoHid;
use crate::tpm::init_tpm;

mod hid;
mod env;
mod tpm;

#[derive(Deserialize)]
struct TuskConfig {
    tcti: String
}

fn main() {
    env_logger::init();

    let (xdg_dirs, config_path) = match init_data() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error initializing data: {:?}", e);
            return;
        }
    };

    let settings = match read_config(config_path) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("Error reading config: {:?}", e);
            return;
        }
    };

    init_tpm(&settings.tcti);

    let device = FidoHid::<File>::new().expect("Failed to create FIDO HID device");
    println!("Virtual FIDO2 HID device created. Waiting for host...");
    let env = TuskEnv::new(device, xdg_dirs);

    if let Err(e) = run_fido_hid(env) {
        eprintln!("Error: {:?}", e);
    }
}

fn init_data() -> Result<(BaseDirectories, PathBuf), io::Error> {
    // Initialize BaseDirectories and get config path

    let xdg_dirs = BaseDirectories::with_prefix("tusk");
    xdg_dirs.create_data_directory("")?;

    let config_path = xdg_dirs.place_config_file("tusk.cfg")?;
    Ok((xdg_dirs, config_path))
}

fn read_config(config_path: PathBuf) -> Result<TuskConfig, config::ConfigError> {
    // Read configuration from file and environment variables and set defaults

    let settings = Config::builder()
        .set_default("tcti", "device:/dev/tpmrm0")?
        .add_source(config::File::from(config_path).format(config::FileFormat::Ini).required(false))
        .add_source(config::Environment::with_prefix("TUSK"))
        .build()?;

    settings.try_deserialize::<TuskConfig>()
}

fn run_fido_hid(env: TuskEnv) -> CtapResult<()> {
    // Main loop for Tusk that constantly processes HID packets

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
