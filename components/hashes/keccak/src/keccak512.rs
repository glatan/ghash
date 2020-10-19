use super::Keccak;
use utils::Hash;

pub struct Keccak512(Keccak);

impl Keccak512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak512 {
    fn default() -> Self {
        Self(Keccak::new(576, 1024, 512))
    }
}

impl Hash for Keccak512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x01);
        self.0.keccak()
    }
}
