use alloc::vec::Vec;

use utils::Hash;

use super::Blake2;

pub struct Blake2s(Blake2<u32>);

impl Blake2s {
    pub fn with_digest_len(n: usize) -> Self {
        Self(Blake2::<u32>::with_digest_len(n))
    }
}

impl Hash for Blake2s {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.l = message.len();
        let l = message.len();
        let mut block = [0u32; 16];
        if l >= 64 {
            message.chunks_exact(64).for_each(|bytes| {
                (0..16).for_each(|i| {
                    block[i] = u32::from_le_bytes([
                        bytes[i * 4],
                        bytes[i * 4 + 1],
                        bytes[i * 4 + 2],
                        bytes[i * 4 + 3],
                    ]);
                });
                self.0.compress(&block);
            });
        } else if l == 0 {
            self.0
                .compress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        if (l % 64) != 0 {
            let offset = (l / 64) * 64;
            let remainder = l % 64;
            let mut bytes = [0u8; 64];
            bytes[..remainder].copy_from_slice(&message[offset..]);
            (0..16).for_each(|i| {
                block[i] = u32::from_le_bytes([
                    bytes[i * 4],
                    bytes[i * 4 + 1],
                    bytes[i * 4 + 2],
                    bytes[i * 4 + 3],
                ]);
            });
            self.0.compress(&block);
        }
        let word_len = {
            if self.0.n < 4 {
                1
            } else {
                self.0.n.next_power_of_two() / 4
            }
        };
        self.0.h[0..word_len]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect::<Vec<u8>>()[0..(self.0.n)]
            .to_vec()
    }
}
