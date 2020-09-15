use super::Hash;
use std::cmp::Ordering;

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
    word_block: Vec<T>,
    salt: [T; 4],
    l: usize, // 未処理のビット数
    h: [T; 8],
    t: [T; 2],  // counter: 処理したビット数(と次に処理をするブロックのビット数?)
    v: [T; 16], // state
    ignore_counter: bool,
}

impl Blake<u32> {
    fn new(h: [u32; 8]) -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            salt: [0; 4],
            l: 0,
            h,
            t: [0; 2],
            v: [0; 16],
            ignore_counter: false,
        }
    }
    fn padding(&mut self, message: &[u8], last_byte: u8) {
        let mut m = message.to_vec();
        let l = message.len();
        self.l = message.len() * 8;
        // 64 - 1(0x80) - 8(l) = 55
        match (l % 64).cmp(&55) {
            Ordering::Greater => {
                m.push(0x80);
                m.append(&mut vec![0; 64 + 54 - (l % 64)]);
                m.push(last_byte);
            }
            Ordering::Less => {
                m.push(0x80);
                m.append(&mut vec![0; 54 - (l % 64)]);
                m.push(last_byte);
            }
            Ordering::Equal => {
                m.push(0x80 | last_byte);
            }
        }
        // append message length
        m.append(&mut (8 * l as u64).to_be_bytes().to_vec());
        // create 32 bit-words from input bytes(and appending bytes)
        for i in (0..m.len()).filter(|i| i % 4 == 0) {
            self.word_block
                .push(u32::from_be_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]));
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
            // if next l == 0
            if self.l == 0 && n < (self.word_block.len() / 16) {
                self.ignore_counter = true;
            }
        }
    }
}

impl Blake<u64> {
    fn new(h: [u64; 8]) -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            salt: [0; 4],
            l: 0,
            h,
            t: [0; 2],
            v: [0; 16],
            ignore_counter: false,
        }
    }
    fn padding(&mut self, message: &[u8], last_byte: u8) {
        let mut m = message.to_vec();
        let l = message.len();
        self.l = message.len() * 8;
        // append 0b1000_0000
        // 128 - 1(0x80) - 16(l) = 111
        match (l % 128).cmp(&111) {
            Ordering::Greater => {
                m.push(0x80);
                m.append(&mut vec![0; 128 + 110 - (l % 128)]);
                m.push(last_byte);
            }
            Ordering::Less => {
                m.push(0x80);
                m.append(&mut vec![0; 110 - (l % 128)]);
                m.push(last_byte);
            }
            Ordering::Equal => {
                m.push(0x80 | last_byte);
            }
        }
        // append message length
        m.append(&mut (8 * l as u128).to_be_bytes().to_vec());
        // create 64 bit-words from input bytes(and appending bytes)
        for i in (0..m.len()).filter(|i| i % 8 == 0) {
            self.word_block.push(u64::from_be_bytes([
                m[i],
                m[i + 1],
                m[i + 2],
                m[i + 3],
                m[i + 4],
                m[i + 5],
                m[i + 6],
                m[i + 7],
            ]));
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
            // if next l == 0
            if self.l == 0 && n < (self.word_block.len() / 16) {
                self.ignore_counter = true;
            }
        }
    }
}
