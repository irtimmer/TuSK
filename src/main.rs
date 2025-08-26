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
    let xdg_dirs = BaseDirectories::with_prefix("tusk");
    xdg_dirs.create_data_directory("")?;

    let config_path = xdg_dirs.place_config_file("tusk.cfg")?;
    Ok((xdg_dirs, config_path))
}

fn read_config(config_path: PathBuf) -> Result<TuskConfig, config::ConfigError> {
    let settings = Config::builder()
        .set_default("tcti", "device:/dev/tpmrm0")?
        .add_source(config::File::from(config_path).format(config::FileFormat::Ini).required(false))
        .add_source(config::Environment::with_prefix("TUSK"))
        .build()?;

    settings.try_deserialize::<TuskConfig>()
}

fn run_fido_hid(env: TuskEnv) -> CtapResult<()> {
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
