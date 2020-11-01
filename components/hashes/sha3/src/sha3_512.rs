use keccak::Keccak;
use utils::Hash;

pub struct Sha3_512(Keccak);

impl Sha3_512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self(Keccak::new(576, 1024, 512))
    }
}

impl Hash for Sha3_512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.keccak(message, 0x06)
    }
}
