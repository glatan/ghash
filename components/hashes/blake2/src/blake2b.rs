use alloc::vec::Vec;

use utils::Hash;

use super::Blake2;

#[derive(Debug)]
pub struct Blake2b(Blake2<u64>);

impl Blake2b {
    pub fn with_digest_len(n: u8) -> Self {
        Self(Blake2::<u64>::with_digest_len(n))
    }
}

impl Hash for Blake2b {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.l = message.len();
        let l = message.len();
        let mut block = [0u64; 16];
        if l >= 128 {
            message.chunks_exact(128).for_each(|bytes| {
                (0..16).for_each(|i| {
                    block[i] = u64::from_le_bytes([
                        bytes[i * 8],
                        bytes[i * 8 + 1],
                        bytes[i * 8 + 2],
                        bytes[i * 8 + 3],
                        bytes[i * 8 + 4],
                        bytes[i * 8 + 5],
                        bytes[i * 8 + 6],
                        bytes[i * 8 + 7],
                    ]);
                });
                self.0.compress(&block);
            });
        } else if l == 0 {
            self.0
                .compress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        if (l % 128) != 0 {
            let offset = (l / 128) * 128;
            let remainder = l % 128;
            let mut bytes = [0u8; 128];
            bytes[..remainder].copy_from_slice(&message[offset..]);
            (0..16).for_each(|i| {
                block[i] = u64::from_le_bytes([
                    bytes[i * 8],
                    bytes[i * 8 + 1],
                    bytes[i * 8 + 2],
                    bytes[i * 8 + 3],
                    bytes[i * 8 + 4],
                    bytes[i * 8 + 5],
                    bytes[i * 8 + 6],
                    bytes[i * 8 + 7],
                ]);
            });
            self.0.compress(&block);
        }
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
