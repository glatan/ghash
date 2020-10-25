use super::{Blake, IV256};
use utils::Hash;

pub struct Blake256(Blake<u32>);

impl Blake256 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new(IV256, salt, 14))
    }
}

impl Default for Blake256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new(IV256, [0; 4], 14))
    }
}

impl Hash for Blake256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x01);
        self.0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
