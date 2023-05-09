use alloc::vec::Vec;

use util::Hash;

use super::{Blake, IV224};

pub struct Blake224(Blake<u32>);

impl Blake224 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new(IV224, salt, 14))
    }
}

impl Default for Blake224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new(IV224, [0; 4], 14))
    }
}

impl Hash for Blake224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x00);
        self.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
