use super::Blake2;
use utils::Hash;

pub struct Blake2s(Blake2<u32>);

impl Blake2s {
    #[rustfmt::skip]
    pub fn new(n: usize, k: usize, salt: [u32; 2]) -> Self {
        Self(Blake2::<u32>::new(n, k, salt))
    }
}

impl Default for Blake2s {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake2::<u32>::default())
    }
}

impl Hash for Blake2s {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message);
        self.0.compress();
        let w_len = {
            if self.0.n < 4 {
                1
            } else {
                self.0.n.next_power_of_two() / 4
            }
        };
        self.0.h[0..w_len]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect::<Vec<u8>>()[0..(self.0.n)]
            .to_vec()
    }
}
