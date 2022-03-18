use alloc::vec::Vec;
use core::cmp::Ordering;

use utils::{impl_md_flow_minimal, Hash};

use crate::{
    consts::{
        {f1, f2, f3, f4, f5}, {H160, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT},
    },
    {round_left_160_minimal, round_right_160_minimal},
};

pub struct Ripemd160 {
    status: [u32; 5],
}

impl Ripemd160 {
    pub fn new() -> Self {
        Self::default()
    }
    #[inline(always)]
    #[rustfmt::skip]
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
        let [mut a_left, mut b_left, mut c_left, mut d_left, mut e_left] = self.status;
        let [mut a_right, mut b_right, mut c_right, mut d_right, mut e_right] = self.status;
        // Round 1
        round_left_160_minimal!(0, t, a_left, b_left, c_left, d_left, e_left, f1, x, 0..16);
        round_right_160_minimal!(0, t, a_right, b_right, c_right, d_right, e_right, f5, x, 0..16);
        // Round 2
        round_left_160_minimal!(1, t, a_left, b_left, c_left, d_left, e_left, f2, x, 16..32);
        round_right_160_minimal!(1, t, a_right, b_right, c_right, d_right, e_right, f4, x, 16..32);
        // Round 3
        round_left_160_minimal!(2, t, a_left, b_left, c_left, d_left, e_left, f3, x, 32..48);
        round_right_160_minimal!(2, t, a_right, b_right, c_right, d_right, e_right, f3, x, 32..48);
        // Round 4
        round_left_160_minimal!(3, t, a_left, b_left, c_left, d_left, e_left, f4, x, 48..64);
        round_right_160_minimal!(3, t, a_right, b_right, c_right, d_right, e_right, f2, x, 48..64);
        // Round 4
        round_left_160_minimal!(4, t, a_left, b_left, c_left, d_left, e_left, f5, x, 64..80);
        round_right_160_minimal!(4, t, a_right, b_right, c_right, d_right, e_right, f1, x, 64..80);

        t = self.status[1].wrapping_add(c_left).wrapping_add(d_right);
        self.status[1] = self.status[2].wrapping_add(d_left).wrapping_add(e_right);
        self.status[2] = self.status[3].wrapping_add(e_left).wrapping_add(a_right);
        self.status[3] = self.status[4].wrapping_add(a_left).wrapping_add(b_right);
        self.status[4] = self.status[0].wrapping_add(b_left).wrapping_add(c_right);
        self.status[0] = t;
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self { status: H160 }
    }
}

impl Hash for Ripemd160 {
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
    use super::Ripemd160;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
        ("".as_bytes(), "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ("a".as_bytes(), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ("abc".as_bytes(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (
            "message digest".as_bytes(),
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        ),
        (&[0x61; 1000000], "52783243c1697bdbe16d37f97f68f08325dc1528"),
    ];
    impl_test!(Ripemd160, official, OFFICIAL, Ripemd160::default());
}
