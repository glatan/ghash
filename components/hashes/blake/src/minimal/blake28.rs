use alloc::vec::Vec;

use super::{Blake, IV224};
use utils::Hash;

pub struct Blake28(Blake<u32>);

impl Blake28 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new(IV224, salt, 10))
    }
}

impl Default for Blake28 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new(IV224, [0; 4], 10))
    }
}

impl Hash for Blake28 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x00);
        self.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
