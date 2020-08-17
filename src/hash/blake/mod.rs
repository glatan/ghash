use super::{Hash, Message};
use crate::{impl_md4_padding, impl_message};
use std::cmp::Ordering;
use std::mem;

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

#[rustfmt::skip]
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
// BLAKE-224(BLAKE-28) and BLAKE-256(BLAKE-32) Constant
#[rustfmt::skip]
const C32: [u32; 16] = [
    0x243F_6A88, 0x85A3_08D3, 0x1319_8A2E, 0x0370_7344, 0xA409_3822, 0x299F_31D0, 0x082E_FA98, 0xEC4E_6C89,
    0x4528_21E6, 0x38D0_1377, 0xBE54_66CF, 0x34E9_0C6C, 0xC0AC_29B7, 0xC97C_50DD, 0x3F84_D5B5, 0xB547_0917
];
// BLAKE-384(BLAKE-48) and BLAKE-512(BLAKE-64) Constant
#[rustfmt::skip]
const C64: [u64; 16] = [
    0x243F_6A88_85A3_08D3, 0x1319_8A2E_0370_7344, 0xA409_3822_299F_31D0, 0x082E_FA98_EC4E_6C89,
    0x4528_21E6_38D0_1377, 0xBE54_66CF_34E9_0C6C, 0xC0AC_29B7_C97C_50DD, 0x3F84_D5B5_B547_0917,
    0x9216_D5D9_8979_FB1B, 0xD131_0BA6_98DF_B5AC, 0x2FFD_72DB_D01A_DFB7, 0xB8E1_AFED_6A26_7E96,
    0xBA7C_9045_F12C_7F99, 0x24A1_9947_B391_6CF7, 0x0801_F2E2_858E_FC16, 0x6369_20D8_7157_4E69
];

// Blake<u32>: BLAKE-224(BLAKE-28) and BLAKE-256(BLAKE-32)
// Blake<u64>: BLAKE-384(BLAKE-48) and BLAKE-512(BLAKE-64)
struct Blake<T> {
    message: Vec<u8>,
    word_block: Vec<T>,
    salt: [T; 4],
    l: Vec<usize>, // length: 各ブロックのビット数(パディングビットのみのブロックのビット数は、一つ前のブロックのビット数に加算し、そのワードのビット数は0とする。)
    h: [T; 8],
    t: [T; 2],  // counter: 処理したビット数(と次に処理をするブロックのビット数?)
    v: [T; 16], // state
    bit: usize, // padding macro用
}

impl Blake<u32> {
    pub fn new(message: &[u8], h: [u32; 8], bit: usize) -> Self {
        let mut l = vec![512; message.len() / 64];
        match (message.len() % 64).cmp(&54) {
            Ordering::Equal => l.push(54 * 8),
            Ordering::Less => l.push((message.len() % 64) * 8),
            Ordering::Greater => {
                l[message.len() - 1] += (message.len() % 64) * 8;
                l.push(0);
            }
        }
        Self {
            message: message.to_vec(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: l,
            h: h,
            t: [0; 2],
            v: [0; 16],
            bit: bit,
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, n: usize, i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // n: block index
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(
            self.word_block[SIGMA[r % 10][2 * i] + 16 * n] ^ C32[SIGMA[r % 10][2 * i + 1]],
        );
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(
            self.word_block[SIGMA[r % 10][2 * i + 1] + 16 * n] ^ C32[SIGMA[r % 10][2 * i]],
        );
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }
    fn compress(&mut self, round_limit: usize) {
        // Compress blocks(1 block == 16 words, 1 word == 32 bit)
        // Compress 1 block in 1 loop
        for n in 0..(self.word_block.len() / 16) {
            // initialize counter
            self.t[0] = (self.t[0] + self.l[n] as u32) & 0xFFFF_FFFF;
            if self.t[0] == 0 {
                self.t[1] += 1;
            }
            // initialize state
            self.v = [
                self.h[0],
                self.h[1],
                self.h[2],
                self.h[3],
                self.h[4],
                self.h[5],
                self.h[6],
                self.h[7],
                self.salt[0] ^ C32[0],
                self.salt[1] ^ C32[1],
                self.salt[2] ^ C32[2],
                self.salt[3] ^ C32[3],
                self.t[0] ^ C32[4],
                self.t[0] ^ C32[5],
                self.t[1] ^ C32[6],
                self.t[1] ^ C32[7],
            ];
            // round
            for r in 0..round_limit {
                self.g(n, 0, r, 0, 4, 8, 12);
                self.g(n, 1, r, 1, 5, 9, 13);
                self.g(n, 2, r, 2, 6, 10, 14);
                self.g(n, 3, r, 3, 7, 11, 15);
                self.g(n, 4, r, 0, 5, 10, 15);
                self.g(n, 5, r, 1, 6, 11, 12);
                self.g(n, 6, r, 2, 7, 8, 13);
                self.g(n, 7, r, 3, 4, 9, 14);
            }
            // finalize
            for i in 0..8 {
                self.h[i] ^= self.salt[i % 4] ^ self.v[i] ^ self.v[i + 8];
            }
        }
    }
}

impl Blake<u32> {
    // Set Message
    impl_message!(self, u64);
    // Padding
    impl_md4_padding!(u32 => self, from_be_bytes, to_be_bytes, 54, {match self.bit {
        // BLAKE-224(BLAKE-28)はパディング末尾が0
        224 => self.message.push(0x00),
        // BLAKE-256(BLAKE-32)はパディング末尾が1
        256 => self.message.push(0x01),
        _ => panic!("Invalid bit: BLAKE-{} is not implemented", self.bit),
    }});
}

impl Blake<u64> {
    pub fn new(message: &[u8], h: [u64; 8], bit: usize) -> Self {
        let mut l = vec![1024; message.len() / 128];
        match (message.len() % 128).cmp(&110) {
            Ordering::Equal => l.push(110 * 8),
            Ordering::Less => l.push((message.len() % 128) * 8),
            Ordering::Greater => {
                l[message.len() - 1] += (message.len() % 128) * 8;
                l.push(0);
            }
        }
        Self {
            message: message.to_vec(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: l,
            h: h,
            t: [0; 2],
            v: [0; 16],
            bit: bit,
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, n: usize, i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // n: block index
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(
            self.word_block[SIGMA[r % 10][2 * i] + 16 * n] ^ C64[SIGMA[r % 10][2 * i + 1]],
        );
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(32);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(25);
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(
            self.word_block[SIGMA[r % 10][2 * i + 1] + 16 * n] ^ C64[SIGMA[r % 10][2 * i]],
        );
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(11);
    }
    fn compress(&mut self, round_limit: usize) {
        // Compress blocks(1 block == 16 words, 1 word == 64 bit)
        // Compress 1 block in 1 loop
        for n in 0..(self.word_block.len() / 16) {
            // initialize counter
            self.t[0] = (self.t[0] + self.l[n] as u64) & 0xFFFFFFFF_FFFFFFFF;
            if self.t[0] == 0 {
                self.t[1] += 1;
            }
            // initialize state
            self.v = [
                self.h[0],
                self.h[1],
                self.h[2],
                self.h[3],
                self.h[4],
                self.h[5],
                self.h[6],
                self.h[7],
                self.salt[0] ^ C64[0],
                self.salt[1] ^ C64[1],
                self.salt[2] ^ C64[2],
                self.salt[3] ^ C64[3],
                self.t[0] ^ C64[4],
                self.t[0] ^ C64[5],
                self.t[1] ^ C64[6],
                self.t[1] ^ C64[7],
            ];
            // round
            for r in 0..round_limit {
                self.g(n, 0, r, 0, 4, 8, 12);
                self.g(n, 1, r, 1, 5, 9, 13);
                self.g(n, 2, r, 2, 6, 10, 14);
                self.g(n, 3, r, 3, 7, 11, 15);
                self.g(n, 4, r, 0, 5, 10, 15);
                self.g(n, 5, r, 1, 6, 11, 12);
                self.g(n, 6, r, 2, 7, 8, 13);
                self.g(n, 7, r, 3, 4, 9, 14);
            }
            // finalize
            for i in 0..8 {
                self.h[i] ^= self.salt[i % 4] ^ self.v[i] ^ self.v[i + 8];
            }
        }
    }
}

impl Blake<u64> {
    // Set Message
    impl_message!(self, u128);
    // Padding
    impl_md4_padding!(u64 => self, from_be_bytes, to_be_bytes, 110, {match self.bit {
        // BLAKE-384(BLAKE-48)はパディング末尾が0
        384 => self.message.push(0x00),
        // BLAKE-512(BLAKE-64)はパディング末尾が1
        512 => self.message.push(0x01),
        _ => panic!("Invalid bit: BLAKE-{} is not implemented", self.bit),
    }});
}
