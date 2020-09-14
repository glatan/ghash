use super::Hash;
use super::{f, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::impl_padding;
use std::cmp::Ordering;

#[rustfmt::skip]
const H320: [u32; 10] = [
    0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
    0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF, 0x0123_4567, 0x3C2D_1E0F
];

pub struct Ripemd320 {
    word_block: Vec<u32>,
    status: [u32; 10],
}

impl Ripemd320 {
    fn new() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: H320,
        }
    }
    fn compress(&mut self) {
        let mut t;
        for i in 0..(self.word_block.len() / 16) {
            let (mut a_left, mut b_left, mut c_left, mut d_left, mut e_left) = (
                self.status[0],
                self.status[1],
                self.status[2],
                self.status[3],
                self.status[4],
            );
            let (mut a_right, mut b_right, mut c_right, mut d_right, mut e_right) = (
                self.status[5],
                self.status[6],
                self.status[7],
                self.status[8],
                self.status[9],
            );
            for j in 0..80 {
                t = a_left
                    .wrapping_add(f(j, b_left, c_left, d_left))
                    .wrapping_add(self.word_block[i * 16 + R_LEFT[j]])
                    .wrapping_add(K160_LEFT[(j / 16)])
                    .rotate_left(S_LEFT[j])
                    .wrapping_add(e_left);
                a_left = e_left;
                e_left = d_left;
                d_left = c_left.rotate_left(10);
                c_left = b_left;
                b_left = t;
                t = a_right
                    .wrapping_add(f(79 - j, b_right, c_right, d_right))
                    .wrapping_add(self.word_block[i * 16 + R_RIGHT[j]])
                    .wrapping_add(K160_RIGHT[(j / 16)])
                    .rotate_left(S_RIGHT[j])
                    .wrapping_add(e_right);
                a_right = e_right;
                e_right = d_right;
                d_right = c_right.rotate_left(10);
                c_right = b_right;
                b_right = t;
                if j == 15 {
                    t = b_left;
                    b_left = b_right;
                    b_right = t;
                } else if j == 31 {
                    t = d_left;
                    d_left = d_right;
                    d_right = t;
                } else if j == 47 {
                    t = a_left;
                    a_left = a_right;
                    a_right = t;
                } else if j == 63 {
                    t = c_left;
                    c_left = c_right;
                    c_right = t;
                } else if j == 79 {
                    t = e_left;
                    e_left = e_right;
                    e_right = t;
                }
            }
            self.status[0] = self.status[0].wrapping_add(a_left);
            self.status[1] = self.status[1].wrapping_add(b_left);
            self.status[2] = self.status[2].wrapping_add(c_left);
            self.status[3] = self.status[3].wrapping_add(d_left);
            self.status[4] = self.status[4].wrapping_add(e_left);
            self.status[5] = self.status[5].wrapping_add(a_right);
            self.status[6] = self.status[6].wrapping_add(b_right);
            self.status[7] = self.status[7].wrapping_add(c_right);
            self.status[8] = self.status[8].wrapping_add(d_right);
            self.status[9] = self.status[9].wrapping_add(e_right);
        }
    }
}

impl Ripemd320 {
    // Padding
    impl_padding!(u32 => self, from_le_bytes, to_le_bytes);
}

impl Hash for Ripemd320 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut ripemd320 = Self::new();
        ripemd320.padding(message);
        ripemd320.compress();
        ripemd320
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
        "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
    ),
    (
        "a".as_bytes(),
        "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
    ),
    (
        "abc".as_bytes(),
        "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
    ),
    (
        "message digest".as_bytes(),
        "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
    ),
    (
        "abcdefghijklmnopqrstuvwxyz".as_bytes(),
        "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
    ),
    (
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
        "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
    ),
    (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
        "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
    ),
    (
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .as_bytes(),
        "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
    ),
    (
        &[0x61; 1000000],
        "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
    ),
];

#[cfg(test)]
impl_test!(Ripemd320);
