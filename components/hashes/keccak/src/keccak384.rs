use super::Keccak;
use utils::Hash;

pub struct Keccak384(Keccak);

impl Keccak384 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak384 {
    fn default() -> Self {
        Self(Keccak::new(832, 768, 384 / 8))
    }
}

impl Hash for Keccak384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x01)
    }
}
