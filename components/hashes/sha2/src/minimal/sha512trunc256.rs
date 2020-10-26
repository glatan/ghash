use super::{Sha2, H512_TRUNC256};
use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

pub struct Sha512Trunc256(Sha2<u64>);

impl Sha512Trunc256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new(H512_TRUNC256))
    }
}

impl Hash for Sha512Trunc256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
