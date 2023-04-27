use alloc::vec::Vec;

use util::Hash;

use crate::KeccakF1600;

pub struct Keccak384(KeccakF1600);

impl Keccak384 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak384 {
    fn default() -> Self {
        Self(KeccakF1600::new(832, 768, 384 / 8))
    }
}

impl Hash for Keccak384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x01)
    }
}
