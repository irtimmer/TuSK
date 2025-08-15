use rand::{Error, SeedableRng};
use rand::rngs::StdRng;

use opensk::api::rng::Rng;
use opensk::api::rng::rand_core::{CryptoRng, RngCore};

pub struct TuskRng(StdRng);

impl Rng for TuskRng {}
impl CryptoRng for TuskRng {}

impl TuskRng {
    pub fn new() -> Self {
        TuskRng(StdRng::from_entropy())
    }
}

impl RngCore for TuskRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}
