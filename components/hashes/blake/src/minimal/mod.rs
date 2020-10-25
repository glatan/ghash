// Round1/2 submission version
mod blake28;
mod blake32;
mod blake48;
mod blake64;

pub use blake28::Blake28;
pub use blake32::Blake32;
pub use blake48::Blake48;
pub use blake64::Blake64;

// Final version
mod blake224;
mod blake256;
mod blake384;
mod blake512;

pub use blake224::Blake224;
pub use blake256::Blake256;
pub use blake384::Blake384;
pub use blake512::Blake512;

use crate::consts::*;
use std::cmp::Ordering;

// Blake<u32>: BLAKE-224(BLAKE-28) and BLAKE-256(BLAKE-32)
// Blake<u64>: BLAKE-384(BLAKE-48) and BLAKE-512(BLAKE-64)
pub(crate) struct Blake<T> {
    salt: [T; 4],
    l: usize, // 未処理のビット数
    pub(crate) h: [T; 8],
    t: [T; 2],  // counter: 処理したビット数(と次に処理をするブロックのビット数?)
    v: [T; 16], // state
    ignore_counter: bool,
    round_limit: usize,
}

impl Blake<u32> {
    pub(crate) fn new(h: [u32; 8], salt: [u32; 4], round_limit: usize) -> Self {
        Self {
            salt,
            l: 0,
            h,
            t: [0; 2],
            v: [0; 16],
            ignore_counter: false,
            round_limit,
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, block: &[u32; 16], i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i]] ^ C32[SIGMA[r % 10][2 * i + 1]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i + 1]] ^ C32[SIGMA[r % 10][2 * i]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }
    fn compress(&mut self, block: &[u32; 16]) {
        // update counter
        if self.l > 512 {
            self.t[0] += 512;
            self.l -= 512;
        } else {
            self.t[0] += self.l as u32;
            self.l = 0;
        }
        // initialize state
        self.v[0] = self.h[0];
        self.v[1] = self.h[1];
        self.v[2] = self.h[2];
        self.v[3] = self.h[3];
        self.v[4] = self.h[4];
        self.v[5] = self.h[5];
        self.v[6] = self.h[6];
        self.v[7] = self.h[7];
        self.v[8] = self.salt[0] ^ C32[0];
        self.v[9] = self.salt[1] ^ C32[1];
        self.v[10] = self.salt[2] ^ C32[2];
        self.v[11] = self.salt[3] ^ C32[3];
        // ブロック数が2以上かつ最後のブロックの処理時にカウンター(l)が0のときはこうするらしい(仕様書内に対応する記述を見つけられていない)。
        if self.ignore_counter {
            self.v[12] = C32[4];
            self.v[13] = C32[5];
            self.v[14] = C32[6];
            self.v[15] = C32[7];
        } else {
            self.v[12] = self.t[0] ^ C32[4];
            self.v[13] = self.t[0] ^ C32[5];
            self.v[14] = self.t[1] ^ C32[6];
            self.v[15] = self.t[1] ^ C32[7];
        }
        // round
        for r in 0..self.round_limit {
            self.g(block, 0, r, 0, 4, 8, 12);
            self.g(block, 1, r, 1, 5, 9, 13);
            self.g(block, 2, r, 2, 6, 10, 14);
            self.g(block, 3, r, 3, 7, 11, 15);
            self.g(block, 4, r, 0, 5, 10, 15);
            self.g(block, 5, r, 1, 6, 11, 12);
            self.g(block, 6, r, 2, 7, 8, 13);
            self.g(block, 7, r, 3, 4, 9, 14);
        }
        // finalize
        for i in 0..8 {
            self.h[i] ^= self.salt[i % 4] ^ self.v[i] ^ self.v[i + 8];
        }
    }
    pub(crate) fn blake(&mut self, message: &[u8], last_byte: u8) {
        self.l = message.len() * 8;
        let l = message.len();
        let mut block = [0u32; 16];
        if l >= 64 {
            message.chunks_exact(64).for_each(|bytes| {
                (0..16).for_each(|i| {
                    block[i] = u32::from_be_bytes([
                        bytes[i * 4 + 0],
                        bytes[i * 4 + 1],
                        bytes[i * 4 + 2],
                        bytes[i * 4 + 3],
                    ]);
                });
                self.compress(&block);
            });
        } else if l == 0 {
            self.compress(&[
                u32::from_be_bytes([0x80, 0, 0, 0]),
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
                0 | last_byte as u32,
                0,
                0,
            ])
        }
        if l != 0 {
            let offset = (l / 64) * 64;
            let remainder = l % 64;
            match (l % 64).cmp(&55) {
                Ordering::Greater => {
                    // two blocks
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[119] |= last_byte;
                    byte_block[120..].copy_from_slice(&(8 * l as u64).to_be_bytes());
                    byte_block.chunks_exact(64).for_each(|bytes| {
                        (0..16).for_each(|i| {
                            block[i] = u32::from_be_bytes([
                                bytes[i * 4 + 0],
                                bytes[i * 4 + 1],
                                bytes[i * 4 + 2],
                                bytes[i * 4 + 3],
                            ]);
                        });
                        self.compress(&block);
                        self.ignore_counter = true;
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 64];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[55] |= last_byte;
                    byte_block[56..].copy_from_slice(&(8 * l as u64).to_be_bytes());
                    (0..16).for_each(|i| {
                        block[i] = u32::from_be_bytes([
                            byte_block[i * 4 + 0],
                            byte_block[i * 4 + 1],
                            byte_block[i * 4 + 2],
                            byte_block[i * 4 + 3],
                        ]);
                    });
                    if self.l == 0 {
                        self.ignore_counter = true;
                    }
                    self.compress(&block);
                }
            }
        }
    }
}

impl Blake<u64> {
    pub(crate) fn new(h: [u64; 8], salt: [u64; 4], round_limit: usize) -> Self {
        Self {
            salt,
            l: 0,
            h,
            t: [0; 2],
            v: [0; 16],
            ignore_counter: false,
            round_limit,
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, block: &[u64; 16], i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i]] ^ C64[SIGMA[r % 10][2 * i + 1]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(32);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(25);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i + 1]] ^ C64[SIGMA[r % 10][2 * i]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(11);
    }
    fn compress(&mut self, block: &[u64; 16]) {
        // update counter
        if self.l > 1024 {
            self.t[0] += 1024;
            self.l -= 1024;
        } else {
            self.t[0] += self.l as u64;
            self.l = 0;
        }
        // initialize state
        self.v[0] = self.h[0];
        self.v[1] = self.h[1];
        self.v[2] = self.h[2];
        self.v[3] = self.h[3];
        self.v[4] = self.h[4];
        self.v[5] = self.h[5];
        self.v[6] = self.h[6];
        self.v[7] = self.h[7];
        self.v[8] = self.salt[0] ^ C64[0];
        self.v[9] = self.salt[1] ^ C64[1];
        self.v[10] = self.salt[2] ^ C64[2];
        self.v[11] = self.salt[3] ^ C64[3];
        // ブロック数が2以上かつ最後のブロックの処理時にカウンター(l)が0のときはこうするらしい(仕様書内に対応する記述を見つけられていない)。
        if self.ignore_counter {
            self.v[12] = C64[4];
            self.v[13] = C64[5];
            self.v[14] = C64[6];
            self.v[15] = C64[7];
        } else {
            self.v[12] = self.t[0] ^ C64[4];
            self.v[13] = self.t[0] ^ C64[5];
            self.v[14] = self.t[1] ^ C64[6];
            self.v[15] = self.t[1] ^ C64[7];
        }
        // round
        for r in 0..self.round_limit {
            self.g(block, 0, r, 0, 4, 8, 12);
            self.g(block, 1, r, 1, 5, 9, 13);
            self.g(block, 2, r, 2, 6, 10, 14);
            self.g(block, 3, r, 3, 7, 11, 15);
            self.g(block, 4, r, 0, 5, 10, 15);
            self.g(block, 5, r, 1, 6, 11, 12);
            self.g(block, 6, r, 2, 7, 8, 13);
            self.g(block, 7, r, 3, 4, 9, 14);
        }
        // finalize
        for i in 0..8 {
            self.h[i] ^= self.salt[i % 4] ^ self.v[i] ^ self.v[i + 8];
        }
    }
    pub(crate) fn blake(&mut self, message: &[u8], last_byte: u8) {
        self.l = message.len() * 8;
        let l = message.len();
        let mut block = [0u64; 16];
        if l >= 128 {
            message.chunks_exact(128).for_each(|bytes| {
                (0..16).for_each(|i| {
                    block[i] = u64::from_be_bytes([
                        bytes[i * 8 + 0],
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
                u64::from_be_bytes([0x80, 0, 0, 0, 0, 0, 0, 0]),
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
                0 | last_byte as u64,
                0,
                0,
            ])
        }
        if l != 0 {
            let offset = (l / 128) * 128;
            let remainder = l % 128;
            match (l % 128).cmp(&111) {
                Ordering::Greater => {
                    // two blocks
                    let mut byte_block = [0u8; 256];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[239] |= last_byte;
                    byte_block[240..].copy_from_slice(&(8 * l as u128).to_be_bytes());
                    byte_block.chunks_exact(128).for_each(|bytes| {
                        (0..16).for_each(|i| {
                            block[i] = u64::from_be_bytes([
                                bytes[i * 8 + 0],
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
                        self.ignore_counter = true;
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[111] |= last_byte;
                    byte_block[112..].copy_from_slice(&(8 * l as u128).to_be_bytes());
                    (0..16).for_each(|i| {
                        block[i] = u64::from_be_bytes([
                            byte_block[i * 8 + 0],
                            byte_block[i * 8 + 1],
                            byte_block[i * 8 + 2],
                            byte_block[i * 8 + 3],
                            byte_block[i * 8 + 4],
                            byte_block[i * 8 + 5],
                            byte_block[i * 8 + 6],
                            byte_block[i * 8 + 7],
                        ]);
                    });
                    if self.l == 0 {
                        self.ignore_counter = true;
                    }
                    self.compress(&block);
                }
            }
        }
    }
}
