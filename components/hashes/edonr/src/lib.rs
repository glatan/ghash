#![no_std]
extern crate alloc;

mod consts;
mod edonr224;
mod edonr256;
mod edonr384;
mod edonr512;

use core::cmp::Ordering;

#[cfg(not(feature = "minimal"))]
use utils::impl_md_flow;
#[cfg(feature = "minimal")]
use utils::impl_md_flow_minimal as impl_md_flow;

use consts::{q256, q512, P224, P256, P384, P512};

pub use edonr224::EdonR224;
pub use edonr256::EdonR256;
pub use edonr384::EdonR384;
pub use edonr512::EdonR512;

struct EdonR<T> {
    state: [T; 16],
}

impl EdonR<u32> {
    fn new(iv: [u32; 16]) -> Self {
        Self { state: iv }
    }
    fn compress(&mut self, message: &[u32; 16]) {
        let mut state_8 = [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        ];
        let mut state_16 = [
            self.state[8],
            self.state[9],
            self.state[10],
            self.state[11],
            self.state[12],
            self.state[13],
            self.state[14],
            self.state[15],
        ];
        let mut state_24;
        let mut state_32;
        // First row of quasigroup e-transformations
        state_24 = q256(
            &[
                message[15],
                message[14],
                message[13],
                message[12],
                message[11],
                message[10],
                message[9],
                message[8],
            ],
            &[
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ],
        );
        state_32 = q256(
            &state_24,
            &[
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ],
        );
        // Second row of quasigroup e-transformations
        state_24 = q256(&state_16, &state_24);
        state_32 = q256(&state_24, &state_32);
        // Third row of quasigroup e-transformations
        state_24 = q256(&state_24, &state_8);
        state_32 = q256(&state_32, &state_24);
        // Fourth row of quasigroup e-transformations
        state_8 = q256(
            &[
                message[7], message[6], message[5], message[4], message[3], message[2], message[1],
                message[0],
            ],
            &state_24,
        );
        state_16 = q256(&state_8, &state_32);
        self.state[0..8].copy_from_slice(&state_8);
        self.state[8..16].copy_from_slice(&state_16);
    }
    fn edonr(&mut self, message: &[u8]) {
        impl_md_flow!(u32=> self, message, from_le_bytes, to_le_bytes);
    }
}

impl EdonR<u64> {
    fn new(iv: [u64; 16]) -> Self {
        Self { state: iv }
    }
    fn compress(&mut self, message: &[u64; 16]) {
        let mut state_8 = [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        ];
        let mut state_16 = [
            self.state[8],
            self.state[9],
            self.state[10],
            self.state[11],
            self.state[12],
            self.state[13],
            self.state[14],
            self.state[15],
        ];
        let mut state_24;
        let mut state_32;
        // First row of quasigroup e-transformations
        state_24 = q512(
            &[
                message[15],
                message[14],
                message[13],
                message[12],
                message[11],
                message[10],
                message[9],
                message[8],
            ],
            &[
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ],
        );
        state_32 = q512(
            &state_24,
            &[
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ],
        );
        // Second row of quasigroup e-transformations
        state_24 = q512(&state_16, &state_24);
        state_32 = q512(&state_24, &state_32);
        // Third row of quasigroup e-transformations
        state_24 = q512(&state_24, &state_8);
        state_32 = q512(&state_32, &state_24);
        // Fourth row of quasigroup e-transformations
        state_8 = q512(
            &[
                message[7], message[6], message[5], message[4], message[3], message[2], message[1],
                message[0],
            ],
            &state_24,
        );
        state_16 = q512(&state_8, &state_32);
        self.state[0..8].copy_from_slice(&state_8);
        self.state[8..16].copy_from_slice(&state_16);
    }
    // EDON-R{384, 512}は、パディング末尾に付与するビット長が64bit分なので`impl_md_flow`マクロを利用していない。
    fn edonr(&mut self, message: &[u8]) {
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
                self.compress(&block);
            });
        } else if l == 0 {
            self.compress(&[
                u64::from_le_bytes([0x80, 0, 0, 0, 0, 0, 0, 0]),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
        }
        if l != 0 {
            let offset = (l / 128) * 128;
            let remainder = l % 128;
            match (l % 128).cmp(&119) {
                Ordering::Greater => {
                    // two blocks
                    let mut byte_block = [0u8; 256];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[248..].copy_from_slice(&(8 * l as u64).to_le_bytes());
                    byte_block.chunks_exact(128).for_each(|bytes| {
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
                        self.compress(&block);
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[120..].copy_from_slice(&(8 * l as u64).to_le_bytes());
                    (0..16).for_each(|i| {
                        block[i] = u64::from_le_bytes([
                            byte_block[i * 8],
                            byte_block[i * 8 + 1],
                            byte_block[i * 8 + 2],
                            byte_block[i * 8 + 3],
                            byte_block[i * 8 + 4],
                            byte_block[i * 8 + 5],
                            byte_block[i * 8 + 6],
                            byte_block[i * 8 + 7],
                        ]);
                    });
                    self.compress(&block);
                }
            }
        }
    }
}
