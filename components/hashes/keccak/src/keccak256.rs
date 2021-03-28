use alloc::vec::Vec;

use crate::KeccakF1600;

use utils::Hash;

pub struct Keccak256(KeccakF1600);

impl Keccak256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self(KeccakF1600::new(1088, 512, 256 / 8))
    }
}

impl Hash for Keccak256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x01)
    }
}
