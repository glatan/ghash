use alloc::vec::Vec;
use core::cmp::Ordering;

use utils::{impl_md_flow_minimal, Hash};

use crate::{
    consts::{
        {f1, f2, f3, f4}, {H128, K128_LEFT, K128_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT},
    },
    {round_left_128_minimal, round_right_128_minimal},
};

pub struct Ripemd128 {
    status: [u32; 4],
}

impl Ripemd128 {
    pub fn new() -> Self {
        Self::default()
    }
    #[inline(always)]
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
        let [mut a_left, mut b_left, mut c_left, mut d_left] = self.status;
        let [mut a_right, mut b_right, mut c_right, mut d_right] = self.status;
        // Round 1
        round_left_128_minimal!(0, t, a_left, b_left, c_left, d_left, f1, x, 0..16);
        round_right_128_minimal!(0, t, a_right, b_right, c_right, d_right, f4, x, 0..16);
        // Round 2
        round_left_128_minimal!(1, t, a_left, b_left, c_left, d_left, f2, x, 16..32);
        round_right_128_minimal!(1, t, a_right, b_right, c_right, d_right, f3, x, 16..32);
        // Round 3
        round_left_128_minimal!(2, t, a_left, b_left, c_left, d_left, f3, x, 32..48);
        round_right_128_minimal!(2, t, a_right, b_right, c_right, d_right, f2, x, 32..48);
        // Round 4
        round_left_128_minimal!(3, t, a_left, b_left, c_left, d_left, f4, x, 48..64);
        round_right_128_minimal!(3, t, a_right, b_right, c_right, d_right, f1, x, 48..64);

        t = self.status[1].wrapping_add(c_left).wrapping_add(d_right);
        self.status[1] = self.status[2].wrapping_add(d_left).wrapping_add(a_right);
        self.status[2] = self.status[3].wrapping_add(a_left).wrapping_add(b_right);
        self.status[3] = self.status[0].wrapping_add(b_left).wrapping_add(c_right);
        self.status[0] = t;
    }
}

impl Default for Ripemd128 {
    fn default() -> Self {
        Self { status: H128 }
    }
}

impl Hash for Ripemd128 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow_minimal!(u32 => self, message, from_le_bytes, to_le_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ripemd128;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
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
    impl_test!(Ripemd128, official, OFFICIAL, Ripemd128::default());
}
