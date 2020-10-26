use super::{Sha2, H384};
use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

pub struct Sha384(Sha2<u64>);

impl Sha384 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha384 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new(H384))
    }
}

impl Hash for Sha384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
