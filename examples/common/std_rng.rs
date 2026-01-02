use rand::{CryptoRng, RngCore};

/// A standard, crypto-compliant random number generator using the `rand` crate which is `Send`.
pub struct StdRng;

impl RngCore for StdRng {
    fn next_u32(&mut self) -> u32 {
        rand::rng().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        rand::rng().next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand::rng().fill_bytes(dst);
    }
}

impl CryptoRng for StdRng {}
