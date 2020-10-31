mod blake2b;
mod blake2s;

pub use blake2b::Blake2b;
pub use blake2s::Blake2s;

use crate::consts::*;
use std::cmp::Ordering;

const fn init_params32(n: usize, k: usize, salt: [u32; 2]) -> [u32; 8] {
    return [
        ((1 << 24) | (1 << 16) | (k << 8) | n) as u32,
        0,               // leaf length
        0,               // node offset
        0,               // node offset(count.), node depth, inner length
        salt[0].to_le(), // salt
        salt[1].to_le(), // salt
        0,               // personalization
        0,               // personalization
    ];
}

const fn init_params64(n: usize, k: usize, salt: [u64; 2]) -> [u64; 8] {
    return [
        ((1 << 24) | (1 << 16) | (k << 8) | n) as u64 | // digest length, key length, fanout, depth
        0, // leaf length
        0, // node offset
        0 |               // node depth, inner length, RFU
        0, // RFU
        0, // RFU
        salt[0].to_le(), // salt
        salt[1].to_le(), // salt
        0, // personalization
        0, // personalization
    ];
}

// Blake<u32>: BLAKE2s
// Blake<u64>: BLAKE2b
struct Blake2<T> {
    f: bool,  // finalization flag
    l: usize, // 未処理のバイト数
    h: [T; 8],
    // p: [T; 8], // parameters
    t: [T; 2],  // counter: 処理したバイト数(と次に処理をするブロックのバイト数?)
    n: usize,   // 出力バイト数
    v: [T; 16], // state
}

// Blake2s
impl Blake2<u32> {
    pub fn new(n: usize, k: usize, salt: [u32; 2]) -> Self {
        if n < 1 || n > 32 {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        let p = init_params32(n, k, salt);
        #[cfg(test)]
        {
            print!("P: ");
            for i in p.iter() {
                print!("{:08x} ", i);
            }
            println!();
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV32[0] ^ p[0],
                IV32[1] ^ p[1],
                IV32[2] ^ p[2],
                IV32[3] ^ p[3],
                IV32[4] ^ p[4],
                IV32[5] ^ p[5],
                IV32[6] ^ p[6],
                IV32[7] ^ p[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, block: &[u32; 16], i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r][2 * i]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r][2 * i + 1]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }
    fn compress(&mut self, block: &[u32; 16]) {
        // update counter
        if self.l > 64 {
            self.t[0] += 64;
            self.l -= 64;
        } else {
            self.t[0] += self.l as u32;
            self.l = 0;
            self.f = true;
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
        self.v[8] = IV32[0];
        self.v[9] = IV32[1];
        self.v[10] = IV32[2];
        self.v[11] = IV32[3];
        self.v[12] = IV32[4] ^ self.t[0];
        self.v[13] = IV32[5] ^ self.t[1];
        if self.f {
            self.v[14] = IV32[6] ^ u32::MAX;
            self.v[15] = IV32[7] ^ u32::MIN;
        } else {
            self.v[14] = IV32[6];
            self.v[15] = IV32[7];
        }
        // round
        for r in 0..10 {
            #[cfg(test)]
            {
                print!("Round[{:}]: ", r);
                for i in 0..16 {
                    print!("{:08x}", self.v[i]);
                }
                println!();
            }
            self.g(block, 0, r, 0, 4, 8, 12);
            self.g(block, 1, r, 1, 5, 9, 13);
            self.g(block, 2, r, 2, 6, 10, 14);
            self.g(block, 3, r, 3, 7, 11, 15);
            self.g(block, 4, r, 0, 5, 10, 15);
            self.g(block, 5, r, 1, 6, 11, 12);
            self.g(block, 6, r, 2, 7, 8, 13);
            self.g(block, 7, r, 3, 4, 9, 14);
        }
        #[cfg(test)]
        {
            print!("Round[{:}]: ", 10);
            for i in 0..16 {
                print!("{:08x}", self.v[i]);
            }
            println!();
        }
        // finalize
        for i in 0..8 {
            self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
        }
    }
    pub(crate) fn blake(&mut self, message: &[u8]) {
        self.l = message.len();
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
                self.compress(&block);
            });
        } else if l == 0 {
            self.compress(&[
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
                0,
            ])
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
            self.compress(&block);
        }
    }
}

impl Default for Blake2<u32> {
    fn default() -> Self {
        Self {
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
        }
    }
}

// Blake2b
impl Blake2<u64> {
    fn new(n: usize, k: usize, salt: [u64; 2]) -> Self {
        if n < 1 || n > 64 {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        let p = init_params64(n, k, salt);
        #[cfg(test)]
        {
            print!("P: ");
            for i in p.iter() {
                print!("{:08x} ", i);
            }
            println!();
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV64[0] ^ p[0],
                IV64[1] ^ p[1],
                IV64[2] ^ p[2],
                IV64[3] ^ p[3],
                IV64[4] ^ p[4],
                IV64[5] ^ p[5],
                IV64[6] ^ p[6],
                IV64[7] ^ p[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, block: &[u64; 16], i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(32);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(24);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(block[SIGMA[r % 10][2 * i + 1]]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(63);
    }
    fn compress(&mut self, block: &[u64; 16]) {
        // update counter
        if self.l > 128 {
            self.t[0] += 128;
            self.l -= 128;
        } else {
            self.t[0] += self.l as u64;
            self.l = 0;
            self.f = true;
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
        self.v[8] = IV64[0];
        self.v[9] = IV64[1];
        self.v[10] = IV64[2];
        self.v[11] = IV64[3];
        self.v[12] = IV64[4] ^ self.t[0];
        self.v[13] = IV64[5] ^ self.t[1];
        if self.f {
            self.v[14] = IV64[6] ^ u64::MAX;
            self.v[15] = IV64[7] ^ u64::MIN;
        } else {
            self.v[14] = IV64[6];
            self.v[15] = IV64[7];
        }
        // round
        for r in 0..12 {
            #[cfg(test)]
            {
                print!("Round[{:}]: ", r);
                for i in 0..16 {
                    print!("{:08x}", self.v[i]);
                }
                println!();
            }
            self.g(block, 0, r, 0, 4, 8, 12);
            self.g(block, 1, r, 1, 5, 9, 13);
            self.g(block, 2, r, 2, 6, 10, 14);
            self.g(block, 3, r, 3, 7, 11, 15);
            self.g(block, 4, r, 0, 5, 10, 15);
            self.g(block, 5, r, 1, 6, 11, 12);
            self.g(block, 6, r, 2, 7, 8, 13);
            self.g(block, 7, r, 3, 4, 9, 14);
        }
        #[cfg(test)]
        {
            print!("Round[{:}]: ", 12);
            for i in 0..16 {
                print!("{:08x}", self.v[i]);
            }
            println!();
        }
        // finalize
        for i in 0..8 {
            self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
        }
    }
    pub(crate) fn blake(&mut self, message: &[u8]) {
        self.l = message.len();
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
                0,
            ])
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
            self.compress(&block);
        }
    }
}

impl Default for Blake2<u64> {
    fn default() -> Self {
        Self {
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
        }
    }
}
