use std::fs::File;

use opensk::env::Env;

use xdg::BaseDirectories;

pub use crypto::TuskCrypto;
pub use rng::TuskRng;
pub use customization::TuskCustomization;
pub use persist::TuskPersist;
pub use write::TuskWrite;

use crate::env::user_presence::PinentryPresence;
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
    presence: PinentryPresence
}

/// Implementation of the `ctap-authenticator` `Env` trait for `TuskEnv`.
///
/// This implementation brings together all the necessary components for the Tusk
/// software authenticator. It specifies the concrete types for various environmental
/// services like random number generation (`TuskRng`), persistent storage (`TuskPersist`),
/// and cryptographic operations (`TuskCrypto`).
///
/// `TuskEnv` itself implements the `UserPresence`, `KeyStore`, and `Clock` traits,
/// so the corresponding methods simply return a reference to `self`.
///
/// The HID connection is defined as `FidoHid<File>`, indicating a file-based
/// transport layer, which is typical for a software authenticator interacting
/// with the host system.
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
    pub fn new(hid: FidoHid<File>, xdg: BaseDirectories) -> Self {
        Self {
            customization: TuskCustomization::new(),
            rng: TuskRng::new(),
            persist: TuskPersist::new(xdg),
            presence: PinentryPresence::default(),
            hid
        }
    }
}
