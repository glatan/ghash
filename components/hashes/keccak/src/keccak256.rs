use super::Keccak;
use utils::Hash;

pub struct Keccak256(Keccak);

impl Keccak256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self(Keccak::new(1088, 512, 256))
    }
}

impl Hash for Keccak256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x01);
        self.0.keccak()
    }
}

