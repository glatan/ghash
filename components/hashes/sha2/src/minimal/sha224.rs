use super::{Sha2, H224};
use core::cmp::Ordering;
use utils::{impl_md_flow_minimal, Hash};

pub struct Sha224(Sha2<u32>);

impl Sha224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u32>::new(H224))
    }
}

impl Hash for Sha224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow_minimal!(u32=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
