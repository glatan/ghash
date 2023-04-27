use alloc::vec::Vec;

use utils::Hash;

use super::{EdonR, P384};

pub struct EdonR384(EdonR<u64>);

impl EdonR384 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EdonR384 {
    fn default() -> Self {
        Self(EdonR::<u64>::new(P384))
    }
}

impl Hash for EdonR384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.edonr(message);
        self.0.state[10..16]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}
