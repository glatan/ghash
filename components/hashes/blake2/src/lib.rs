#![no_std]

extern crate alloc;

mod blake2b;
mod blake2s;
mod consts;
mod params;

pub use params::{Blake2bParams, Blake2sParams, Blake2xbParams, Blake2xsParams};

use crate::consts::{IV32, IV64, SIGMA};

pub use blake2b::Blake2b;
pub use blake2s::Blake2s;

#[inline(always)]
fn g32(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
fn g64(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[derive(Debug)]
struct Blake2<T> {
    f: bool,  // finalization flag
    l: usize, // 未処理のバイト数
    h: [T; 8],
    t: [T; 2],  // counter: 処理したバイト数(と次に処理をするブロックのバイト数?)
    n: usize,   // 出力バイト数
    v: [T; 16], // state
}

macro_rules! impl_blake2 {
    (Word = $Word:ty;
        Params = $Params:ty, IV = $IV:expr, BlockLength = $BlockLength:expr;
        for 0..$RoundLimit:expr => fn $g:ident
    ) => {
        impl Blake2<$Word> {
            pub const fn with_digest_len(digest_len: u8) -> Self {
                let params = <$Params>::with_digest_len(digest_len).to_words();
                Self {
                    f: false,
                    l: 0,
                    h: [
                        $IV[0] ^ params[0],
                        $IV[1],
                        $IV[2],
                        $IV[3],
                        $IV[4],
                        $IV[5],
                        $IV[6],
                        $IV[7],
                    ],
                    t: [0; 2],
                    n: digest_len as usize,
                    v: [0; 16],
                }
            }
            #[inline(always)]
            fn compress(&mut self, block: &[$Word; 16]) {
                // update counter
                if self.l > $BlockLength {
                    self.t[0] += $BlockLength;
                    self.l -= $BlockLength;
                } else {
                    self.t[0] += self.l as $Word;
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
                self.v[8] = $IV[0];
                self.v[9] = $IV[1];
                self.v[10] = $IV[2];
                self.v[11] = $IV[3];
                self.v[12] = $IV[4] ^ self.t[0];
                self.v[13] = $IV[5] ^ self.t[1];
                if self.f {
                    self.v[14] = $IV[6] ^ <$Word>::MAX;
                    self.v[15] = $IV[7] ^ <$Word>::MIN;
                } else {
                    self.v[14] = $IV[6];
                    self.v[15] = $IV[7];
                }
                // round
                for r in 0..$RoundLimit {
                    $g(
                        &mut self.v,
                        0,
                        4,
                        8,
                        12,
                        block[SIGMA[r % 10][2 * 0]],
                        block[SIGMA[r % 10][2 * 0 + 1]],
                    );
                    $g(
                        &mut self.v,
                        1,
                        5,
                        9,
                        13,
                        block[SIGMA[r % 10][2 * 1]],
                        block[SIGMA[r % 10][2 * 1 + 1]],
                    );
                    $g(
                        &mut self.v,
                        2,
                        6,
                        10,
                        14,
                        block[SIGMA[r % 10][2 * 2]],
                        block[SIGMA[r % 10][2 * 2 + 1]],
                    );
                    $g(
                        &mut self.v,
                        3,
                        7,
                        11,
                        15,
                        block[SIGMA[r % 10][2 * 3]],
                        block[SIGMA[r % 10][2 * 3 + 1]],
                    );
                    $g(
                        &mut self.v,
                        0,
                        5,
                        10,
                        15,
                        block[SIGMA[r % 10][2 * 4]],
                        block[SIGMA[r % 10][2 * 4 + 1]],
                    );
                    $g(
                        &mut self.v,
                        1,
                        6,
                        11,
                        12,
                        block[SIGMA[r % 10][2 * 5]],
                        block[SIGMA[r % 10][2 * 5 + 1]],
                    );
                    $g(
                        &mut self.v,
                        2,
                        7,
                        8,
                        13,
                        block[SIGMA[r % 10][2 * 6]],
                        block[SIGMA[r % 10][2 * 6 + 1]],
                    );
                    $g(
                        &mut self.v,
                        3,
                        4,
                        9,
                        14,
                        block[SIGMA[r % 10][2 * 7]],
                        block[SIGMA[r % 10][2 * 7 + 1]],
                    );
                }
                // finalize
                for i in 0..8 {
                    self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
                }
            }
        }
    };
}

impl_blake2!(Word = u32;
    Params = Blake2sParams, IV = IV32, BlockLength = 64;
    for 0..10 => fn g32
);
impl_blake2!(Word = u64;
    Params = Blake2bParams, IV = IV64, BlockLength = 128;
    for 0..12 => fn g64
);
