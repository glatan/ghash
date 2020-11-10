use alloc::vec::Vec;

use super::{Blake, IV384};
use utils::Hash;

pub struct Blake48(Blake<u64>);

impl Blake48 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new(IV384, salt, 14))
    }
}

impl Default for Blake48 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new(IV384, [0; 4], 14))
    }
}

impl Hash for Blake48 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x00);
        self.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
