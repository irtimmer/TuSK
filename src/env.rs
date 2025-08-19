use std::fs::File;

use opensk::env::Env;

pub use crypto::TuskCrypto;
pub use rng::TuskRng;
pub use customization::TuskCustomization;
pub use persist::TuskPersist;
pub use write::TuskWrite;

use crate::hid::FidoHid;

mod clock;
mod customization;
mod crypto;
mod key_store;
mod persist;
mod rng;
mod user_presence;
mod write;

pub struct TuskEnv {
    customization: TuskCustomization,
    rng: TuskRng,
    persist: TuskPersist,
    hid: FidoHid<File>,
}

impl Env for TuskEnv {
    type Rng = TuskRng;
    type UserPresence = Self;
    type Persist = TuskPersist;
    type KeyStore = Self;
    type Clock = Self;
    type Write = TuskWrite;
    type Customization = TuskCustomization;
    type HidConnection = FidoHid<File>;
    type Crypto = TuskCrypto;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self {
        self
    }

    fn persist(&mut self) -> &mut Self::Persist {
        &mut self.persist
    }

    fn key_store(&mut self) -> &mut Self {
        self
    }

    fn clock(&mut self) -> &mut Self {
        self
    }

    fn write(&mut self) -> Self::Write {
        TuskWrite
    }

    fn customization(&self) -> &Self::Customization {
        &self.customization
    }

    fn hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.hid
    }

    fn boots_after_soft_reset(&self) -> bool {
        true
    }

    fn firmware_version(&self) -> Option<u64> {
        None
    }
}

impl TuskEnv {
    pub fn new(hid: FidoHid<File>) -> Self {
        Self {
            customization: TuskCustomization::new(),
            rng: TuskRng::new(),
            persist: TuskPersist::new(),
            hid
        }
    }
}
