use alloc::vec::Vec;

use utils::Hash;

use super::{Blake, IV256};

pub struct Blake32(Blake<u32>);

impl Blake32 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new(IV256, salt, 10))
    }
}

impl Default for Blake32 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new(IV256, [0; 4], 10))
    }
}

impl Hash for Blake32 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x01);
        self.0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
