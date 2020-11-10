use alloc::vec::Vec;

use keccak::Keccak;
use utils::Hash;

pub struct Shake256(Keccak);

impl Shake256 {
    pub fn new(n: usize) -> Self {
        Self(Keccak::new(1088, 512, n))
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new(256 / 8)
    }
}

impl Hash for Shake256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x1F)
    }
}
