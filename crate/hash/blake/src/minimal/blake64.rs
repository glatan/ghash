use alloc::vec::Vec;

use util::Hash;

use super::{Blake, IV512};

pub struct Blake64(Blake<u64>);

impl Blake64 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new(IV512, salt, 14))
    }
}

impl Default for Blake64 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new(IV512, [0; 4], 14))
    }
}

impl Hash for Blake64 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x01);
        self.0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
