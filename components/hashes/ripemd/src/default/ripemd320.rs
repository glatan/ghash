use alloc::vec::Vec;
use core::{cmp::Ordering, mem};

use utils::{impl_md_flow, uint_from_bytes, Hash};

use crate::{
    consts::{
        {f1, f2, f3, f4, f5}, {H320, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT},
    },
    {round_left_160, round_right_160},
};

pub struct Ripemd320 {
    status: [u32; 10],
}

impl Ripemd320 {
    pub fn new() -> Self {
        Self::default()
    }
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
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
        // Round 1
        round_left_160!(
            t, a_left, b_left, c_left, d_left, e_left, f1, x, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            12, 13, 14, 15
        );
        round_right_160!(
            t, a_right, b_right, c_right, d_right, e_right, f5, x, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, 11, 12, 13, 14, 15
        );
        mem::swap(&mut b_left, &mut b_right);
        // Round 2
        round_left_160!(
            t, a_left, b_left, c_left, d_left, e_left, f2, x, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31
        );
        round_right_160!(
            t, a_right, b_right, c_right, d_right, e_right, f4, x, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );
        mem::swap(&mut d_left, &mut d_right);
        // Round 3
        round_left_160!(
            t, a_left, b_left, c_left, d_left, e_left, f3, x, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47
        );
        round_right_160!(
            t, a_right, b_right, c_right, d_right, e_right, f3, x, 32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47
        );
        mem::swap(&mut a_left, &mut a_right);
        // Round 4
        round_left_160!(
            t, a_left, b_left, c_left, d_left, e_left, f4, x, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63
        );
        round_right_160!(
            t, a_right, b_right, c_right, d_right, e_right, f2, x, 48, 49, 50, 51, 52, 53, 54, 55,
            56, 57, 58, 59, 60, 61, 62, 63
        );
        mem::swap(&mut c_left, &mut c_right);
        // Round 5
        round_left_160!(
            t, a_left, b_left, c_left, d_left, e_left, f5, x, 64, 65, 66, 67, 68, 69, 70, 71, 72,
            73, 74, 75, 76, 77, 78, 79
        );
        round_right_160!(
            t, a_right, b_right, c_right, d_right, e_right, f1, x, 64, 65, 66, 67, 68, 69, 70, 71,
            72, 73, 74, 75, 76, 77, 78, 79
        );
        mem::swap(&mut e_left, &mut e_right);

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

impl Default for Ripemd320 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            status: H320,
        }
    }
}

impl Hash for Ripemd320 {
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
    use super::Ripemd320;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
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
    impl_test!(Ripemd320, official, OFFICIAL, Ripemd320::default());
}
