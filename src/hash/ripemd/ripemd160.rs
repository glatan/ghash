use super::{f, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use super::{Hash, Input};
use crate::{impl_input, impl_md4_padding};
use std::cmp::Ordering;
use std::mem;

const H160: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

pub struct Ripemd160 {
    message: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 5],
}

impl Ripemd160 {
    pub const fn new() -> Self {
        Self {
            message: Vec::new(),
            word_block: Vec::new(),
            status: H160,
        }
    }
    fn round(&mut self) {
        let mut t;
        for i in 0..(self.word_block.len() / 16) {
            let [mut a_left, mut b_left, mut c_left, mut d_left, mut e_left] = self.status;
            let [mut a_right, mut b_right, mut c_right, mut d_right, mut e_right] = self.status;
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
            }
            t = self.status[1].wrapping_add(c_left).wrapping_add(d_right);
            self.status[1] = self.status[2].wrapping_add(d_left).wrapping_add(e_right);
            self.status[2] = self.status[3].wrapping_add(e_left).wrapping_add(a_right);
            self.status[3] = self.status[4].wrapping_add(a_left).wrapping_add(b_right);
            self.status[4] = self.status[0].wrapping_add(b_left).wrapping_add(c_right);
            self.status[0] = t;
        }
    }
}

impl Ripemd160 {
    // Padding
    impl_md4_padding!(u32 => self, from_le_bytes, to_le_bytes, 55, {});
}

impl Input for Ripemd160 {
    // Set Message
    impl_input!(self, u64);
}

impl Hash for Ripemd160 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut ripemd160 = Self::new();
        ripemd160.input(message);
        ripemd160.padding();
        ripemd160.round();
        ripemd160
            .status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ripemd160;
    use crate::hash::Test;
    impl Test<Ripemd160> for Ripemd160 {}
    // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
    const TEST_CASES: [(&[u8], &str); 9] = [
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
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd160::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd160::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Ripemd160::compare_uppercase(i, e);
        }
    }
}
