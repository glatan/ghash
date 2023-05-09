use alloc::vec::Vec;

use util::Hash;

use super::Blake2;
use crate::consts::IV64;

pub struct Blake2b(Blake2<u64>);

impl Blake2b {
    pub fn new(n: usize) -> Self {
        Self(Blake2::<u64>::new(n))
    }
    pub fn with_key(n: usize, k: usize, salt: [u64; 2], personal: [u64; 2]) -> Self {
        Self(Blake2::<u64>::with_key(n, k, salt, personal))
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        Self(Blake2::<u64> {
            f: false,
            l: 0,
            h: [
                // Default parameter(0x40 bytes of output length, 0x00 byte of key length, set fanout and depth to 0x01)
                IV64[0] ^ 0x0101_0040,
                IV64[1],
                IV64[2],
                IV64[3],
                IV64[4],
                IV64[5],
                IV64[6],
                IV64[7],
            ],
            t: [0; 2],
            n: 64,
            v: [0; 16],
        })
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
