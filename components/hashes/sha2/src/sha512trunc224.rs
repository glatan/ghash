use alloc::vec::Vec;
use core::cmp::Ordering;

use super::{impl_md_flow, Sha2, H512_TRUNC224};
use utils::Hash;

pub struct Sha512Trunc224(Sha2<u64>);

impl Sha512Trunc224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new(H512_TRUNC224))
    }
}

impl Hash for Sha512Trunc224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .take(224 / 8) // (224 / 8) bytes
            .collect()
    }
}
