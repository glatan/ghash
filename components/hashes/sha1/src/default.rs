use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::consts::*;
use utils::{impl_md_flow, uint_from_bytes, Hash};

macro_rules! init_w {
    ( $w:expr, $( $t:expr ),* ) => {
        $(
            $w[$t] = ($w[$t - 3] ^ $w[$t - 8] ^ $w[$t - 14] ^ $w[$t - 16]).rotate_left(1);
        )*
    };
}

macro_rules! round {
    ($temp:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $w:expr, $( $t:expr ),+) => {
        $(
            $temp = $a
                .rotate_left(5)
                .wrapping_add($f($b, $c, $d))
                .wrapping_add($e)
                .wrapping_add($w[$t])
                .wrapping_add(K[$t / 20]);
            $e = $d;
            $d = $c;
            $c = $b.rotate_left(30);
            $b = $a;
            $a = $temp;
        )*
    };
}

const fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}
const fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
const fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

pub struct Sha1 {
    status: [u32; 5],
}

impl Sha1 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names)]
    fn compress(&mut self, m: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d, mut e] = self.status;
        let mut temp;

        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        init_w!(
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79
        );

        // Round 1
        round!(
            temp, a, b, c, d, e, ch, w, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19
        );
        // Round 2
        round!(
            temp, a, b, c, d, e, parity, w, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
            34, 35, 36, 37, 38, 39
        );
        // Round 3
        round!(
            temp, a, b, c, d, e, maj, w, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59
        );
        // Round 4
        round!(
            temp, a, b, c, d, e, parity, w, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
            74, 75, 76, 77, 78, 79
        );

        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
        self.status[4] = self.status[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            status: IV,
        }
    }
}

impl Hash for Sha1 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32=> self, message, from_be_bytes, to_be_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
