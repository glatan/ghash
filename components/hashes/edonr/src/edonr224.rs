use super::{EdonR, P224};
use utils::Hash;

pub struct EdonR224(EdonR<u32>);

impl EdonR224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EdonR224 {
    fn default() -> Self {
        Self(EdonR::<u32>::new(P224))
    }
}

impl Hash for EdonR224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.edonr(message);
        self.0.state[9..16]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}
