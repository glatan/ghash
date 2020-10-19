use keccak::Keccak;
use utils::Hash;

pub struct Sha3_384(Keccak);

impl Sha3_384 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_384 {
    fn default() -> Self {
        Self(Keccak::new(832, 768, 384))
    }
}

impl Hash for Sha3_384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x06);
        self.0.keccak()
    }
}
