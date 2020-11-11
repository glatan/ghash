use super::{EdonR, P224};
use core::cmp::Ordering;
use utils::{impl_md_flow_minimal, Hash};

pub struct EdonR224(EdonR<u32>);

impl EdonR224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EdonR224 {
    fn default() -> Self {
        Self(EdonR::new(P224))
    }
}

impl Hash for EdonR224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow_minimal!(u32=> self.0, message, from_le_bytes, to_le_bytes);
        self.0.state[9..16]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}
