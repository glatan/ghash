use crate::consts::*;
use core::cmp::Ordering;
use utils::{uint_from_bytes, Hash};

macro_rules! g32 {
    ($self:ident, $block:expr, $r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i]] ^ C32[SIGMA[$r % 10][2 * $i + 1]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(16);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(12);
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i + 1]] ^ C32[SIGMA[$r % 10][2 * $i]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(8);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(7);
    };
}
macro_rules! g64 {
    ($self:ident, $block:expr, $r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i]] ^ C64[SIGMA[$r % 10][2 * $i + 1]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(32);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(25);
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i + 1]] ^ C64[SIGMA[$r % 10][2 * $i]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(16);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(11);
    };
}

// u32
// 64 - 1(0x80) - 8(l) = 55
// u64
// 128 - 1(0x80) - 16(l) = 111
macro_rules! impl_blake32 {
    ($T:ident, $h:expr, $outlen:expr, $last_byte:expr, $( $r:expr ),+) => {
        pub struct $T {
            salt: [u32; 4],
            l: usize,
            h: [u32; 8],
            t: [u32; 2],
            v: [u32; 16],
            ignore_counter: bool,
        }
        impl $T {
            pub fn new(salt: [u32; 4]) -> Self {
                Self {
                    salt,
                    l: 0,
                    h: $h,
                    t: [0; 2],
                    v: [0; 16],
                    ignore_counter: false,
                }
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
                $(
                    g32!(self, block, $r, 0, 0, 4, 8, 12);
                    g32!(self, block, $r, 1, 1, 5, 9, 13);
                    g32!(self, block, $r, 2, 2, 6, 10, 14);
                    g32!(self, block, $r, 3, 3, 7, 11, 15);
                    g32!(self, block, $r, 4, 0, 5, 10, 15);
                    g32!(self, block, $r, 5, 1, 6, 11, 12);
                    g32!(self, block, $r, 6, 2, 7, 8, 13);
                    g32!(self, block, $r, 7, 3, 4, 9, 14);
                )*
                // finalize
                self.h[0] ^= self.salt[0 % 4] ^ self.v[0] ^ self.v[0 + 8];
                self.h[1] ^= self.salt[1 % 4] ^ self.v[1] ^ self.v[1 + 8];
                self.h[2] ^= self.salt[2 % 4] ^ self.v[2] ^ self.v[2 + 8];
                self.h[3] ^= self.salt[3 % 4] ^ self.v[3] ^ self.v[3 + 8];
                self.h[4] ^= self.salt[4 % 4] ^ self.v[4] ^ self.v[4 + 8];
                self.h[5] ^= self.salt[5 % 4] ^ self.v[5] ^ self.v[5 + 8];
                self.h[6] ^= self.salt[6 % 4] ^ self.v[6] ^ self.v[6 + 8];
                self.h[7] ^= self.salt[7 % 4] ^ self.v[7] ^ self.v[7 + 8];
            }
        }
        impl Default for $T {
            fn default() -> Self {
                Self {
                    salt: [0; 4],
                    l: 0,
                    h: $h,
                    t: [0; 2],
                    v: [0; 16],
                    ignore_counter: false,
                }
            }
        }
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                self.l = message.len() * 8;
                let l = message.len();
                let mut block = [0u32; 16];
                if l >= 64 {
                    message.chunks_exact(64).for_each(|bytes| {
                        uint_from_bytes!(u32 => 0, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 1, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 2, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 3, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 4, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 5, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 6, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 7, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 8, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 9, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 10, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 11, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 12, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 13, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 14, block, bytes, from_be_bytes);
                        uint_from_bytes!(u32 => 15, block, bytes, from_be_bytes);
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
                        0 | $last_byte as u32,
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
                            byte_block[119] |= $last_byte;
                            byte_block[120..].copy_from_slice(&(8 * l as u64).to_be_bytes());
                            byte_block.chunks_exact(64).for_each(|bytes| {
                                uint_from_bytes!(u32 => 0, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 1, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 2, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 3, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 4, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 5, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 6, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 7, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 8, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 9, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 10, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 11, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 12, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 13, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 14, block, bytes, from_be_bytes);
                                uint_from_bytes!(u32 => 15, block, bytes, from_be_bytes);
                                self.compress(&block);
                                self.ignore_counter = true;
                            });
                        }
                        Ordering::Less | Ordering::Equal => {
                            // one block
                            let mut byte_block = [0u8; 64];
                            byte_block[..remainder].copy_from_slice(&message[offset..]);
                            byte_block[remainder] = 0x80;
                            byte_block[55] |= $last_byte;
                            byte_block[56..].copy_from_slice(&(8 * l as u64).to_be_bytes());
                            uint_from_bytes!(u32 => 0, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 1, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 2, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 3, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 4, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 5, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 6, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 7, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 8, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 9, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 10, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 11, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 12, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 13, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 14, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u32 => 15, block, byte_block, from_be_bytes);
                            if self.l == 0 {
                                self.ignore_counter = true;
                            }
                            self.compress(&block);
                        }
                    }
                }
                self.h[$outlen]
                    .iter()
                    .flat_map(|word| word.to_be_bytes().to_vec())
                    .collect()
            }
        }
    };
}
macro_rules! impl_blake64 {
    ($T:ident, $h:expr, $outlen:expr, $last_byte:expr, $( $r:expr ),*) => {
        pub struct $T {
            salt: [u64; 4],
            l: usize,
            h: [u64; 8],
            t: [u64; 2],
            v: [u64; 16],
            ignore_counter: bool,
        }
        impl $T {
            pub fn new(salt: [u64; 4]) -> Self {
                Self {
                    salt,
                    l: 0,
                    h: $h,
                    t: [0; 2],
                    v: [0; 16],
                    ignore_counter: false,
                }
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
                $(
                    g64!(self, block, $r, 0, 0, 4, 8, 12);
                    g64!(self, block, $r, 1, 1, 5, 9, 13);
                    g64!(self, block, $r, 2, 2, 6, 10, 14);
                    g64!(self, block, $r, 3, 3, 7, 11, 15);
                    g64!(self, block, $r, 4, 0, 5, 10, 15);
                    g64!(self, block, $r, 5, 1, 6, 11, 12);
                    g64!(self, block, $r, 6, 2, 7, 8, 13);
                    g64!(self, block, $r, 7, 3, 4, 9, 14);
                )*
                // finalize
                self.h[0] ^= self.salt[0 % 4] ^ self.v[0] ^ self.v[0 + 8];
                self.h[1] ^= self.salt[1 % 4] ^ self.v[1] ^ self.v[1 + 8];
                self.h[2] ^= self.salt[2 % 4] ^ self.v[2] ^ self.v[2 + 8];
                self.h[3] ^= self.salt[3 % 4] ^ self.v[3] ^ self.v[3 + 8];
                self.h[4] ^= self.salt[4 % 4] ^ self.v[4] ^ self.v[4 + 8];
                self.h[5] ^= self.salt[5 % 4] ^ self.v[5] ^ self.v[5 + 8];
                self.h[6] ^= self.salt[6 % 4] ^ self.v[6] ^ self.v[6 + 8];
                self.h[7] ^= self.salt[7 % 4] ^ self.v[7] ^ self.v[7 + 8];
            }
        }
        impl Default for $T {
            fn default() -> Self {
                Self {
                    salt: [0; 4],
                    l: 0,
                    h: $h,
                    t: [0; 2],
                    v: [0; 16],
                    ignore_counter: false,
                }
            }
        }
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                self.l = message.len() * 8;
                let l = message.len();
                let mut block = [0u64; 16];
                if l >= 128 {
                    message.chunks_exact(128).for_each(|bytes| {
                        uint_from_bytes!(u64 => 0, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 1, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 2, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 3, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 4, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 5, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 6, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 7, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 8, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 9, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 10, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 11, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 12, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 13, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 14, block, bytes, from_be_bytes);
                        uint_from_bytes!(u64 => 15, block, bytes, from_be_bytes);
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
                        0 | $last_byte as u64,
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
                            byte_block[239] |= $last_byte;
                            byte_block[240..].copy_from_slice(&(8 * l as u128).to_be_bytes());
                            byte_block.chunks_exact(128).for_each(|bytes| {
                                uint_from_bytes!(u64 => 0, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 1, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 2, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 3, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 4, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 5, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 6, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 7, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 8, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 9, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 10, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 11, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 12, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 13, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 14, block, bytes, from_be_bytes);
                                uint_from_bytes!(u64 => 15, block, bytes, from_be_bytes);
                                self.compress(&block);
                                self.ignore_counter = true;
                            });
                        }
                        Ordering::Less | Ordering::Equal => {
                            // one block
                            let mut byte_block = [0u8; 128];
                            byte_block[..remainder].copy_from_slice(&message[offset..]);
                            byte_block[remainder] = 0x80;
                            byte_block[111] |= $last_byte;
                            byte_block[112..].copy_from_slice(&(8 * l as u128).to_be_bytes());
                            uint_from_bytes!(u64 => 0, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 1, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 2, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 3, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 4, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 5, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 6, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 7, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 8, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 9, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 10, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 11, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 12, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 13, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 14, block, byte_block, from_be_bytes);
                            uint_from_bytes!(u64 => 15, block, byte_block, from_be_bytes);
                            if self.l == 0 {
                                self.ignore_counter = true;
                            }
                            self.compress(&block);
                        }
                    }
                }
                self.h[$outlen]
                    .iter()
                    .flat_map(|word| word.to_be_bytes().to_vec())
                    .collect()
            }
        }
    };
}

impl_blake32!(Blake28, IV224, 0..7, 0x00, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
impl_blake32!(Blake32, IV256, 0..8, 0x01, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
#[rustfmt::skip]
impl_blake64!(
    Blake48,
    IV384,
    0..6,
    0x00,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
);
#[rustfmt::skip]
impl_blake64!(
    Blake64,
    IV512,
    0..8,
    0x01,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
);
#[rustfmt::skip]
impl_blake32!(
    Blake224,
    IV224,
    0..7,
    0x00,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
);
#[rustfmt::skip]
impl_blake32!(
    Blake256,
    IV256,
    0..8,
    0x01,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
);
#[rustfmt::skip]
impl_blake64!(
    Blake384,
    IV384,
    0..6,
    0x00,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
);
#[rustfmt::skip]
impl_blake64!(
    Blake512,
    IV512,
    0..8,
    0x01,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
);
