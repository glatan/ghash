use alloc::vec::Vec;

use utils::Hash;

use super::Blake2;
use crate::consts::IV32;

pub struct Blake2s(Blake2<u32>);

impl Blake2s {
    pub fn new(n: usize) -> Self {
        Self(Blake2::<u32>::new(n))
    }
    pub fn with_key(n: usize, k: usize, salt: [u32; 2], personal: [u32; 2]) -> Self {
        Self(Blake2::<u32>::with_key(n, k, salt, personal))
    }
}

impl Default for Blake2s {
    fn default() -> Self {
        Self(Blake2::<u32> {
            f: false,
            l: 0,
            h: [
                // Default parameter(0x20 bytes of output length, 0x00 byte of key length, set fanout and depth to 0x01)
                IV32[0] ^ 0x0101_0020,
                IV32[1],
                IV32[2],
                IV32[3],
                IV32[4],
                IV32[5],
                IV32[6],
                IV32[7],
            ],
            t: [0; 2],
            n: 32,
            v: [0; 16],
        })
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
