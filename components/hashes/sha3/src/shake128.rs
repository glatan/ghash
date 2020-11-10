use alloc::vec::Vec;

use keccak::Keccak;
use utils::Hash;

pub struct Shake128(Keccak);

impl Shake128 {
    pub fn new(n: usize) -> Self {
        Self(Keccak::new(1344, 256, n))
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new(128 / 8)
    }
}

impl Hash for Shake128 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x1F)
    }
}
