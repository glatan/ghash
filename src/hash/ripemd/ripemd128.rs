use super::Hash;
use super::{f, K128_LEFT, K128_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::{impl_input, impl_md4_padding};
use std::cmp::Ordering;
use std::mem;

const H128: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

pub struct Ripemd128 {
    message: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 4],
}

impl Ripemd128 {
    // Set Message
    impl_input!(self, u64);
    // Padding
    impl_md4_padding!(u32 => self, from_le_bytes, to_le_bytes, 55, {});
}

impl Ripemd128 {
    pub const fn new() -> Self {
        Self {
            message: Vec::new(),
            word_block: Vec::new(),
            status: H128,
        }
    }
    fn round(&mut self) {
        let mut t;
        for i in 0..(self.word_block.len() / 16) {
            let [mut a_left, mut b_left, mut c_left, mut d_left] = self.status;
            let [mut a_right, mut b_right, mut c_right, mut d_right] = self.status;
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
            }
            t = self.status[1].wrapping_add(c_left).wrapping_add(d_right);
            self.status[1] = self.status[2].wrapping_add(d_left).wrapping_add(a_right);
            self.status[2] = self.status[3].wrapping_add(a_left).wrapping_add(b_right);
            self.status[3] = self.status[0].wrapping_add(b_left).wrapping_add(c_right);
            self.status[0] = t;
        }
    }
}

impl Hash for Ripemd128 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut ripemd128 = Self::new();
        ripemd128.input(message);
        ripemd128.padding();
        ripemd128.round();
        ripemd128
            .status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ripemd128;
    use crate::hash::Test;
    impl Test<Ripemd128> for Ripemd128 {}
    // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
    const TEST_CASES: [(&[u8], &str); 9] = [
        ("".as_bytes(), "cdf26213a150dc3ecb610f18f6b38b46"),
        ("a".as_bytes(), "86be7afa339d0fc7cfc785e72f578d33"),
        ("abc".as_bytes(), "c14a12199c66e4ba84636b0f69144c77"),
        (
            "message digest".as_bytes(),
            "9e327b3d6e523062afc1132d7df9d1b8",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "fd2aa607f71dc8f510714922b371834e",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "a1aa0689d0fafa2ddc22e88b49133a06",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "d1e959eb179c911faea4624c60c5c702",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "3f45ef194732c2dbb2c4a2c769795fa3",
        ),
        (&[0x61; 1000000], "4a7f5723f954eba1216c9d8f6320431f"),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd128::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd128::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd128::compare_uppercase(i, e);
        }
    }
}
