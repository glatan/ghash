use super::Keccak;
use utils::Hash;

pub struct Keccak224(Keccak);

impl Keccak224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak224 {
    fn default() -> Self {
        Self(Keccak::new(1152, 448, 224))
    }
}

impl Hash for Keccak224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        // self.0.padding();
        self.0.keccak(message, 0x01)
    }
}
