use alloc::vec::Vec;
use core::cmp::Ordering;

use super::{Sha2, H512};
use utils::{impl_md_flow_minimal, Hash};

pub struct Sha512(Sha2<u64>);

impl Sha512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new(H512))
    }
}

impl Hash for Sha512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow_minimal!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0
            .status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
