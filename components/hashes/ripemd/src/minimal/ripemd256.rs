use crate::consts::{f1, f2, f3, f4};
use crate::consts::{H256, K128_LEFT, K128_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use utils::{impl_md_flow, uint_from_bytes, Hash};

use std::cmp::Ordering;
use std::mem;

macro_rules! round_left {
    ($j:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $f:ident, $x:expr) => {
        $t = $a
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($x[R_LEFT[$j]])
            .wrapping_add(K128_LEFT[($j / 16)])
            .rotate_left(S_LEFT[$j]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $t;
    };
}
macro_rules! round_right {
    ($j:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $f:ident, $x:expr) => {
        $t = $a
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($x[R_RIGHT[$j]])
            .wrapping_add(K128_RIGHT[($j / 16)])
            .rotate_left(S_RIGHT[$j]);
        $a = $d;
        $d = $c;
        $c = $b;
        $b = $t;
    };
}

pub struct Ripemd256 {
    status: [u32; 8],
}

impl Ripemd256 {
    pub fn new() -> Self {
        Self::default()
    }
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
        let [mut a_left, mut b_left, mut c_left, mut d_left] = [
            self.status[0],
            self.status[1],
            self.status[2],
            self.status[3],
        ];
        let [mut a_right, mut b_right, mut c_right, mut d_right] = [
            self.status[4],
            self.status[5],
            self.status[6],
            self.status[7],
        ];
        // Round 1
        round_left!(0, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(1, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(2, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(3, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(4, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(5, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(6, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(7, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(8, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(9, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(10, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(11, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(12, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(13, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(14, t, a_left, b_left, c_left, d_left, f1, x);
        round_left!(15, t, a_left, b_left, c_left, d_left, f1, x);
        round_right!(0, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(1, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(2, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(3, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(4, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(5, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(6, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(7, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(8, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(9, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(10, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(11, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(12, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(13, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(14, t, a_right, b_right, c_right, d_right, f4, x);
        round_right!(15, t, a_right, b_right, c_right, d_right, f4, x);
        mem::swap(&mut a_left, &mut a_right);
        // Round 2
        round_left!(16, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(17, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(18, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(19, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(20, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(21, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(22, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(23, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(24, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(25, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(26, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(27, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(28, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(29, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(30, t, a_left, b_left, c_left, d_left, f2, x);
        round_left!(31, t, a_left, b_left, c_left, d_left, f2, x);
        round_right!(16, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(17, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(18, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(19, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(20, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(21, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(22, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(23, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(24, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(25, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(26, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(27, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(28, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(29, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(30, t, a_right, b_right, c_right, d_right, f3, x);
        round_right!(31, t, a_right, b_right, c_right, d_right, f3, x);
        mem::swap(&mut b_left, &mut b_right);
        // Round 3
        round_left!(32, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(33, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(34, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(35, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(36, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(37, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(38, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(39, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(40, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(41, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(42, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(43, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(44, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(45, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(46, t, a_left, b_left, c_left, d_left, f3, x);
        round_left!(47, t, a_left, b_left, c_left, d_left, f3, x);
        round_right!(32, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(33, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(34, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(35, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(36, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(37, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(38, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(39, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(40, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(41, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(42, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(43, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(44, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(45, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(46, t, a_right, b_right, c_right, d_right, f2, x);
        round_right!(47, t, a_right, b_right, c_right, d_right, f2, x);
        mem::swap(&mut c_left, &mut c_right);
        // Round 4
        round_left!(48, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(49, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(50, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(51, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(52, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(53, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(54, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(55, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(56, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(57, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(58, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(59, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(60, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(61, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(62, t, a_left, b_left, c_left, d_left, f4, x);
        round_left!(63, t, a_left, b_left, c_left, d_left, f4, x);
        round_right!(48, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(49, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(50, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(51, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(52, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(53, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(54, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(55, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(56, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(57, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(58, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(59, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(60, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(61, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(62, t, a_right, b_right, c_right, d_right, f1, x);
        round_right!(63, t, a_right, b_right, c_right, d_right, f1, x);
        mem::swap(&mut d_left, &mut d_right);

        self.status[0] = self.status[0].wrapping_add(a_left);
        self.status[1] = self.status[1].wrapping_add(b_left);
        self.status[2] = self.status[2].wrapping_add(c_left);
        self.status[3] = self.status[3].wrapping_add(d_left);
        self.status[4] = self.status[4].wrapping_add(a_right);
        self.status[5] = self.status[5].wrapping_add(b_right);
        self.status[6] = self.status[6].wrapping_add(c_right);
        self.status[7] = self.status[7].wrapping_add(d_right);
    }
}

impl Default for Ripemd256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            status: H256,
        }
    }
}

impl Hash for Ripemd256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32 => self, message, from_le_bytes, to_le_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ripemd256;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        (
            "".as_bytes(),
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        ),
        (
            "a".as_bytes(),
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
        ),
        (
            "abc".as_bytes(),
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        ),
        (
            "message digest".as_bytes(),
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
        ),
        (
            &[0x61; 1000000],
            "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
        ),
    ];
    impl_test!(Ripemd256, official, OFFICIAL, Ripemd256::default());
}
