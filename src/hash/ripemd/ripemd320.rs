use super::Hash;
use super::{f1, f2, f3, f4, f5};
use super::{K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::impl_md_flow;

use std::cmp::Ordering;
use std::mem;

macro_rules! round_left {
    ($j:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $x:expr) => {
        $t = $a
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($x[R_LEFT[$j]])
            .wrapping_add(K160_LEFT[($j / 16)])
            .rotate_left(S_LEFT[$j])
            .wrapping_add($e);
        $a = $e;
        $e = $d;
        $d = $c.rotate_left(10);
        $c = $b;
        $b = $t;
    };
}
macro_rules! round_right {
    ($j:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $x:expr) => {
        $t = $a
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($x[R_RIGHT[$j]])
            .wrapping_add(K160_RIGHT[($j / 16)])
            .rotate_left(S_RIGHT[$j])
            .wrapping_add($e);
        $a = $e;
        $e = $d;
        $d = $c.rotate_left(10);
        $c = $b;
        $b = $t;
    };
}

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
        round_left!(0, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(1, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(2, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(3, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(4, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(5, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(6, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(7, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(8, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(9, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(10, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(11, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(12, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(13, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(14, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_left!(15, t, a_left, b_left, c_left, d_left, e_left, f1, x);
        round_right!(0, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(1, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(2, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(3, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(4, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(5, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(6, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(7, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(8, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(9, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(10, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(11, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(12, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(13, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(14, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        round_right!(15, t, a_right, b_right, c_right, d_right, e_right, f5, x);
        mem::swap(&mut b_left, &mut b_right);
        // Round 2
        round_left!(16, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(17, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(18, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(19, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(20, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(21, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(22, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(23, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(24, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(25, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(26, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(27, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(28, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(29, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(30, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_left!(31, t, a_left, b_left, c_left, d_left, e_left, f2, x);
        round_right!(16, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(17, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(18, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(19, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(20, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(21, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(22, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(23, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(24, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(25, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(26, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(27, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(28, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(29, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(30, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        round_right!(31, t, a_right, b_right, c_right, d_right, e_right, f4, x);
        mem::swap(&mut d_left, &mut d_right);
        // Round 3
        round_left!(32, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(33, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(34, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(35, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(36, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(37, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(38, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(39, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(40, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(41, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(42, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(43, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(44, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(45, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(46, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_left!(47, t, a_left, b_left, c_left, d_left, e_left, f3, x);
        round_right!(32, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(33, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(34, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(35, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(36, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(37, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(38, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(39, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(40, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(41, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(42, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(43, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(44, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(45, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(46, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        round_right!(47, t, a_right, b_right, c_right, d_right, e_right, f3, x);
        mem::swap(&mut a_left, &mut a_right);
        // Round 4
        round_left!(48, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(49, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(50, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(51, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(52, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(53, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(54, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(55, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(56, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(57, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(58, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(59, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(60, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(61, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(62, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_left!(63, t, a_left, b_left, c_left, d_left, e_left, f4, x);
        round_right!(48, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(49, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(50, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(51, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(52, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(53, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(54, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(55, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(56, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(57, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(58, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(59, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(60, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(61, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(62, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        round_right!(63, t, a_right, b_right, c_right, d_right, e_right, f2, x);
        mem::swap(&mut c_left, &mut c_right);
        // Round 5
        round_left!(64, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(65, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(66, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(67, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(68, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(69, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(70, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(71, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(72, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(73, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(74, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(75, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(76, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(77, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(78, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_left!(79, t, a_left, b_left, c_left, d_left, e_left, f5, x);
        round_right!(64, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(65, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(66, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(67, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(68, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(69, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(70, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(71, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(72, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(73, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(74, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(75, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(76, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(77, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(78, t, a_right, b_right, c_right, d_right, e_right, f1, x);
        round_right!(79, t, a_right, b_right, c_right, d_right, e_right, f1, x);
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
            status: [
                0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
                0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF, 0x0123_4567, 0x3C2D_1E0F
            ],
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
    use crate::impl_test;

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
