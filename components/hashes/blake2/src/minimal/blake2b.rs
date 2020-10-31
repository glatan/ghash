use super::Blake2;
use utils::Hash;

pub struct Blake2b(Blake2<u64>);

impl Blake2b {
    #[rustfmt::skip]
    pub fn new(n: usize) -> Self {
        Self(Blake2::<u64>::new(n))
    }
    pub fn with_key(n: usize, k: usize, salt: [u64; 2], personal: [u64; 2]) -> Self {
        Self(Blake2::<u64>::with_key(n, k, salt, personal))
    }
}

impl Default for Blake2b {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake2::<u64>::default())
    }
}

impl Hash for Blake2b {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message);
        let word_len = {
            if self.0.n < 8 {
                1
            } else {
                self.0.n.next_power_of_two() / 8
            }
        };
        self.0.h[0..word_len]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect::<Vec<u8>>()[0..(self.0.n)]
            .to_vec()
    }
}
