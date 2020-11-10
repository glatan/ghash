use crate::consts::{f1, f2, f3, f4};
use crate::consts::{H256, K128_LEFT, K128_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::{round_left_128, round_right_128};
use utils::{impl_md_flow, uint_from_bytes, Hash};

use core::cmp::Ordering;
use core::mem;

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
        round_left_128!(
            t, a_left, b_left, c_left, d_left, f1, x, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            14, 15
        );
        round_right_128!(
            t, a_right, b_right, c_right, d_right, f4, x, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15
        );
        mem::swap(&mut a_left, &mut a_right);
        // Round 2
        round_left_128!(
            t, a_left, b_left, c_left, d_left, f2, x, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27, 28, 29, 30, 31
        );
        round_right_128!(
            t, a_right, b_right, c_right, d_right, f3, x, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31
        );
        mem::swap(&mut b_left, &mut b_right);
        // Round 3
        round_left_128!(
            t, a_left, b_left, c_left, d_left, f3, x, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
            43, 44, 45, 46, 47
        );
        round_right_128!(
            t, a_right, b_right, c_right, d_right, f2, x, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
            42, 43, 44, 45, 46, 47
        );
        mem::swap(&mut c_left, &mut c_right);
        // Round 4
        round_left_128!(
            t, a_left, b_left, c_left, d_left, f4, x, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63
        );
        round_right_128!(
            t, a_right, b_right, c_right, d_right, f1, x, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            58, 59, 60, 61, 62, 63
        );
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
