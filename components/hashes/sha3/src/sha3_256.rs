use keccak::Keccak;
use utils::Hash;

pub struct Sha3_256(Keccak);

impl Sha3_256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self(Keccak::new(1088, 512, 256))
    }
}

impl Hash for Sha3_256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x06)
    }
}
