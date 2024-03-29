use alloc::vec::Vec;

use util::Hash;

use super::{Blake, IV384};

pub struct Blake384(Blake<u64>);

impl Blake384 {
    #[rustfmt::skip]
    pub const fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new(IV384, salt, 16))
    }
}

impl Default for Blake384 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new(IV384, [0; 4], 16))
    }
}

impl Hash for Blake384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x00);
        self.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
