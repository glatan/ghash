use super::{EdonR, P512};
use utils::Hash;

pub struct EdonR512(EdonR<u64>);

impl EdonR512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EdonR512 {
    fn default() -> Self {
        Self(EdonR::<u64>::new(P512))
    }
}

impl Hash for EdonR512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.edonr(message);
        self.0.state[8..16]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}
