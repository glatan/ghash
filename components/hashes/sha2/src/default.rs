use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::consts::*;
use utils::{impl_md_flow, uint_from_bytes, Hash};

macro_rules! init_w32 {
    ($w:expr, $( $t:expr ),* ) => {
        $(
            $w[$t] = small_sigma32_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma32_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}
macro_rules! init_w64 {
    ($w:expr, $( $t:expr ),*) => {
        $(
            $w[$t] = small_sigma64_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma64_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}

macro_rules! round_32 {
    ($temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $( $t:expr ),+) => {
        $(
            $temp_1 = $h
                .wrapping_add(big_sigma32_1($e))
                .wrapping_add(ch32($e, $f, $g))
                .wrapping_add(K32[$t])
                .wrapping_add($w[$t]);
            $temp_2 = big_sigma32_0($a).wrapping_add(maj32($a, $b, $c));
            $h = $g;
            $g = $f;
            $f = $e;
            $e = $d.wrapping_add($temp_1);
            $d = $c;
            $c = $b;
            $b = $a;
            $a = $temp_1.wrapping_add($temp_2);
        )*
    };
}
macro_rules! round_64 {
    ($temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $( $t:expr ),+) => {
        $(
            $temp_1 = $h
                .wrapping_add(big_sigma64_1($e))
                .wrapping_add(ch64($e, $f, $g))
                .wrapping_add(K64[$t])
                .wrapping_add($w[$t]);
            $temp_2 = big_sigma64_0($a).wrapping_add(maj64($a, $b, $c));
            $h = $g;
            $g = $f;
            $f = $e;
            $e = $d.wrapping_add($temp_1);
            $d = $c;
            $c = $b;
            $b = $a;
            $a = $temp_1.wrapping_add($temp_2);
        )*
    };
}

macro_rules! impl_sha2_32 {
    ($T:ident, $h:expr, $outlen:expr) => {
        pub struct $T([u32; 8]);
        impl $T {
            pub fn new() -> Self {
                Self::default()
            }
            #[allow(clippy::many_single_char_names)]
            fn compress(&mut self, m: &[u32; 16]) {
                let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.0;
                let (mut temp_1, mut temp_2);

                let mut w = [0; 64];
                w[..16].copy_from_slice(m);
                init_w32!(
                    w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
                    59, 60, 61, 62, 63
                );

                round_32!(temp_1, temp_2, a, b, c, d, e, f, g, h, w, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                    34, 35, 36,37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                    56, 57, 58, 59, 60, 61, 62, 63
                );

                self.0[0] = self.0[0].wrapping_add(a);
                self.0[1] = self.0[1].wrapping_add(b);
                self.0[2] = self.0[2].wrapping_add(c);
                self.0[3] = self.0[3].wrapping_add(d);
                self.0[4] = self.0[4].wrapping_add(e);
                self.0[5] = self.0[5].wrapping_add(f);
                self.0[6] = self.0[6].wrapping_add(g);
                self.0[7] = self.0[7].wrapping_add(h);
            }
        }
        impl Default for $T {
            fn default() -> Self {
                Self($h)
            }
        }
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                impl_md_flow!(u32=> self, message, from_be_bytes, to_be_bytes);
                self.0[$outlen]
                    .iter()
                    .flat_map(|word| word.to_be_bytes().to_vec())
                    .collect()
            }
        }
    }
}

macro_rules! impl_sha2_64 {
    ($T:ident, $h:expr, $outlen:expr, $truncate_length:expr) => {
        pub struct $T([u64; 8]);
        impl $T {
            pub fn new() -> Self {
                Self::default()
            }
            #[allow(clippy::many_single_char_names)]
            fn compress(&mut self, m: &[u64; 16]) {
                let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.0;
                let (mut temp_1, mut temp_2);

                let mut w = [0; 80];
                w[..16].copy_from_slice(m);
                init_w64!(
                    w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
                    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 77, 78, 79
                );

                round_64!(temp_1, temp_2, a, b, c, d, e, f, g, h, w, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                    34, 35, 36,37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                    56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
                    78, 79
                );

                self.0[0] = self.0[0].wrapping_add(a);
                self.0[1] = self.0[1].wrapping_add(b);
                self.0[2] = self.0[2].wrapping_add(c);
                self.0[3] = self.0[3].wrapping_add(d);
                self.0[4] = self.0[4].wrapping_add(e);
                self.0[5] = self.0[5].wrapping_add(f);
                self.0[6] = self.0[6].wrapping_add(g);
                self.0[7] = self.0[7].wrapping_add(h);
            }
        }
        impl Default for $T {
            fn default() -> Self {
                Self($h)
            }
        }
        impl Hash for $T {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                impl_md_flow!(u64=> self, message, from_be_bytes, to_be_bytes);
                self.0[$outlen]
                    .iter()
                    .flat_map(|word| word.to_be_bytes().to_vec())
                    .take($truncate_length)
                    .collect()
            }
        }
    }
}

impl_sha2_32!(Sha224, H224, 0..7);
impl_sha2_32!(Sha256, H256, 0..8);
impl_sha2_64!(Sha384, H384, 0..6, 384 / 8);
impl_sha2_64!(Sha512, H512, 0..8, 512 / 8);
impl_sha2_64!(Sha512Trunc224, H512_TRUNC224, 0..4, 224 / 8);
impl_sha2_64!(Sha512Trunc256, H512_TRUNC256, 0..4, 256 / 8);
