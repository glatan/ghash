use keccak::Keccak;
use utils::Hash;

pub struct Sha3_224(Keccak);

impl Sha3_224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self(Keccak::new(1152, 448, 224))
    }
}

impl Hash for Sha3_224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x06)
    }
}
