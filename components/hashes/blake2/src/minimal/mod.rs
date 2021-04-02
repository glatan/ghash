mod blake2b;
mod blake2s;

pub use blake2b::Blake2b;
pub use blake2s::Blake2s;

use crate::consts::{IV32, IV64, SIGMA};

struct Blake2<T> {
    f: bool,  // finalization flag
    l: usize, // 未処理のバイト数
    h: [T; 8],
    t: [T; 2],  // counter: 処理したバイト数(と次に処理をするブロックのバイト数?)
    n: usize,   // 出力バイト数
    v: [T; 16], // state
}

impl Blake2<u32> {
    fn new(n: usize) -> Self {
        if !(1..=32).contains(&n) {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV32[0] ^ (0x0101_0000 | n as u32),
                IV32[1],
                IV32[2],
                IV32[3],
                IV32[4],
                IV32[5],
                IV32[6],
                IV32[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    fn with_key(n: usize, k: usize, salt: [u32; 2], personal: [u32; 2]) -> Self {
        if !(1..=32).contains(&n) {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        if k > 32 {
            panic!("{} is not a valid number. k must be between 0 and 32.", k)
        }
        if k == 0 {
            return Self::new(n);
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV32[0] ^ (0x0101_0000 | (k << 8) as u32 | n as u32),
                IV32[1],
                IV32[2],
                IV32[3],
                IV32[4] ^ salt[0].swap_bytes(),
                IV32[5] ^ salt[1].swap_bytes(),
                IV32[6] ^ personal[0].swap_bytes(),
                IV32[7] ^ personal[1].swap_bytes(),
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
            self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
        }
    }
}

impl Blake2<u64> {
    fn new(n: usize) -> Self {
        if !(1..=64).contains(&n) {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV64[0] ^ (0x0101_0000 | n as u64),
                IV64[1],
                IV64[2],
                IV64[3],
                IV64[4],
                IV64[5],
                IV64[6],
                IV64[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    fn with_key(n: usize, k: usize, salt: [u64; 2], personal: [u64; 2]) -> Self {
        if !(1..=64).contains(&n) {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        if k > 64 {
            panic!("{} is not a valid number. k must be between 0 and 64.", k)
        }
        if k == 0 {
            return Self::new(n);
        }
        Self {
            f: false,
            l: 0,
            h: [
                IV64[0] ^ (0x0101_0000 | (k << 8) as u64 | n as u64),
                IV64[1],
                IV64[2],
                IV64[3],
                IV64[4] ^ salt[0].swap_bytes(),
                IV64[5] ^ salt[1].swap_bytes(),
                IV64[6] ^ personal[0].swap_bytes(),
                IV64[7] ^ personal[1].swap_bytes(),
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
            self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
        }
    }
}
