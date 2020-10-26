use super::{Sha2, H256};
use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

pub struct Sha256(Sha2<u32>);

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u32>::new(H256))
    }
}

impl Hash for Sha256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32=> self.0, message, from_be_bytes, to_be_bytes);
        self.0
            .status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
