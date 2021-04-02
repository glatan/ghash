use alloc::vec::Vec;

use keccak::KeccakF1600;
use utils::Hash;

pub struct Sha3_224(KeccakF1600);

impl Sha3_224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self(KeccakF1600::new(1152, 448, 224 / 8))
    }
}

impl Hash for Sha3_224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x06)
    }
}
