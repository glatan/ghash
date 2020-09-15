use super::Hash;
use super::{f, K128_LEFT, K128_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::impl_padding;
use std::cmp::Ordering;

pub struct Ripemd256 {
    word_block: Vec<u32>,
    status: [u32; 8],
}

impl Ripemd256 {
    pub fn new() -> Self {
        Self::default()
    }
    fn compress(&mut self) {
        let mut t;
        for i in 0..(self.word_block.len() / 16) {
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
            for j in 0..64 {
                t = a_left
                    .wrapping_add(f(j, b_left, c_left, d_left))
                    .wrapping_add(self.word_block[i * 16 + R_LEFT[j]])
                    .wrapping_add(K128_LEFT[(j / 16)])
                    .rotate_left(S_LEFT[j]);
                a_left = d_left;
                d_left = c_left;
                c_left = b_left;
                b_left = t;
                t = a_right
                    .wrapping_add(f(63 - j, b_right, c_right, d_right))
                    .wrapping_add(self.word_block[i * 16 + R_RIGHT[j]])
                    .wrapping_add(K128_RIGHT[(j / 16)])
                    .rotate_left(S_RIGHT[j]);
                a_right = d_right;
                d_right = c_right;
                c_right = b_right;
                b_right = t;
                if j == 15 {
                    t = a_left;
                    a_left = a_right;
                    a_right = t;
                } else if j == 31 {
                    t = b_left;
                    b_left = b_right;
                    b_right = t;
                } else if j == 47 {
                    t = c_left;
                    c_left = c_right;
                    c_right = t;
                } else if j == 63 {
                    t = d_left;
                    d_left = d_right;
                    d_right = t;
                }
            }
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
}

impl Ripemd256 {
    impl_padding!(u32 => self, from_le_bytes, to_le_bytes);
}

impl Default for Ripemd256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: [
                0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476,
                0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF, 0x0123_4567
            ],
        }
    }
}

impl Hash for Ripemd256 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut ripemd256 = Self::default();
        ripemd256.padding(message);
        ripemd256.compress();
        ripemd256
            .status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
const TEST_CASES: [(&[u8], &str); 9] = [
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

#[cfg(test)]
impl_test!(Ripemd256);
