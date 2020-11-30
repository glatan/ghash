use alloc::vec::Vec;

use crate::consts::*;
use utils::{uint_from_bytes, Hash};

macro_rules! g32 {
    ($self:ident, $block:expr, $r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(16);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(12);
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i + 1]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(8);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(7);
    };
}
macro_rules! g64 {
    ($self:ident, $block:expr, $r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(32);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(24);
        $self.v[$a] = $self.v[$a]
            .wrapping_add($self.v[$b])
            .wrapping_add($block[SIGMA[$r % 10][2 * $i + 1]]);
        $self.v[$d] = ($self.v[$d] ^ $self.v[$a]).rotate_right(16);
        $self.v[$c] = $self.v[$c].wrapping_add($self.v[$d]);
        $self.v[$b] = ($self.v[$b] ^ $self.v[$c]).rotate_right(63);
    };
}

macro_rules! impl_blake2s {
    ($T:ident, $( $r:expr ),+) => {
        pub struct $T {
            f: bool,
            l: usize,
            h: [u32; 8],
            t: [u32; 2],
            n: usize,
            v: [u32; 16],
        }
        impl $T {
            pub fn new(n: usize) -> Self {
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
            pub fn with_key(n: usize, k: usize, salt: [u32; 2], personal: [u32; 2]) -> Self {
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
                self.h[0] = self.h[0] ^ self.v[0] ^ self.v[0 + 8];
                self.h[1] = self.h[1] ^ self.v[1] ^ self.v[1 + 8];
                self.h[2] = self.h[2] ^ self.v[2] ^ self.v[2 + 8];
                self.h[3] = self.h[3] ^ self.v[3] ^ self.v[3 + 8];
                self.h[4] = self.h[4] ^ self.v[4] ^ self.v[4 + 8];
                self.h[5] = self.h[5] ^ self.v[5] ^ self.v[5 + 8];
                self.h[6] = self.h[6] ^ self.v[6] ^ self.v[6 + 8];
                self.h[7] = self.h[7] ^ self.v[7] ^ self.v[7 + 8];
            }
        }
        impl Default for $T {
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
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                self.l = message.len();
                let l = message.len();
                let mut block = [0u32; 16];
                if l >= 64 {
                    message.chunks_exact(64).for_each(|bytes| {
                        uint_from_bytes!(u32 => 0, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 1, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 2, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 3, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 4, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 5, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 6, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 7, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 8, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 9, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 10, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 11, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 12, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 13, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 14, block, bytes, from_le_bytes);
                        uint_from_bytes!(u32 => 15, block, bytes, from_le_bytes);
                        self.compress(&block);
                    });
                } else if l == 0 {
                    self.compress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                }
                if (l % 64) != 0 {
                    let offset = (l / 64) * 64;
                    let remainder = l % 64;
                    let mut bytes = [0u8; 64];
                    bytes[..remainder].copy_from_slice(&message[offset..]);
                    uint_from_bytes!(u32 => 0, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 1, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 2, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 3, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 4, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 5, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 6, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 7, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 8, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 9, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 10, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 11, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 12, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 13, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 14, block, bytes, from_le_bytes);
                    uint_from_bytes!(u32 => 15, block, bytes, from_le_bytes);
                    self.compress(&block);
                }
                let word_len = {
                    if self.n < 4 {
                        1
                    } else {
                        self.n.next_power_of_two() / 4
                    }
                };
                self.h[0..word_len]
                    .iter()
                    .flat_map(|word| word.to_le_bytes().to_vec())
                    .collect::<Vec<u8>>()[0..(self.n)]
                    .to_vec()
            }
        }
    }
}
macro_rules! impl_blake2b {
    ($T:ident, $( $r:expr ),*) => {
        pub struct $T {
            f: bool,
            l: usize,
            h: [u64; 8],
            t: [u64; 2],
            n: usize,
            v: [u64; 16],
        }
        impl $T {
            pub fn new(n: usize) -> Self {
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
            pub fn with_key(n: usize, k: usize, salt: [u64; 2], personal: [u64; 2]) -> Self {
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
                self.h[0] = self.h[0] ^ self.v[0] ^ self.v[0 + 8];
                self.h[1] = self.h[1] ^ self.v[1] ^ self.v[1 + 8];
                self.h[2] = self.h[2] ^ self.v[2] ^ self.v[2 + 8];
                self.h[3] = self.h[3] ^ self.v[3] ^ self.v[3 + 8];
                self.h[4] = self.h[4] ^ self.v[4] ^ self.v[4 + 8];
                self.h[5] = self.h[5] ^ self.v[5] ^ self.v[5 + 8];
                self.h[6] = self.h[6] ^ self.v[6] ^ self.v[6 + 8];
                self.h[7] = self.h[7] ^ self.v[7] ^ self.v[7 + 8];
            }
        }
        impl Default for $T {
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
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                self.l = message.len();
                let l = message.len();
                let mut block = [0u64; 16];
                if l >= 128 {
                    message.chunks_exact(128).for_each(|bytes| {
                        uint_from_bytes!(u64 => 0, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 1, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 2, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 3, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 4, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 5, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 6, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 7, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 8, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 9, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 10, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 11, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 12, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 13, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 14, block, bytes, from_le_bytes);
                        uint_from_bytes!(u64 => 15, block, bytes, from_le_bytes);
                        self.compress(&block);
                    });
                } else if l == 0 {
                    self.compress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                }
                if (l % 128) != 0 {
                    let offset = (l / 128) * 128;
                    let remainder = l % 128;
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    uint_from_bytes!(u64 => 0, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 1, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 2, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 3, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 4, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 5, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 6, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 7, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 8, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 9, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 10, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 11, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 12, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 13, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 14, block, byte_block, from_le_bytes);
                    uint_from_bytes!(u64 => 15, block, byte_block, from_le_bytes);
                    self.compress(&block);
                }
                let word_len = {
                    if self.n < 8 {
                        1
                    } else {
                        self.n.next_power_of_two() / 8
                    }
                };
                self.h[0..word_len]
                    .iter()
                    .flat_map(|word| word.to_le_bytes().to_vec())
                    .collect::<Vec<u8>>()[0..(self.n)]
                    .to_vec()
            }
        }
    };
}

impl_blake2s!(Blake2s, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
impl_blake2b!(Blake2b, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
