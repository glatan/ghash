use crate::consts::{f1, f2, f3, f4, f5};
use crate::consts::{H160, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use utils::{impl_md_flow, uint_from_bytes, Hash};

use std::cmp::Ordering;

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

pub struct Ripemd160 {
    status: [u32; 5],
}

impl Ripemd160 {
    pub fn new() -> Self {
        Self::default()
    }
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
        let [mut a_left, mut b_left, mut c_left, mut d_left, mut e_left] = self.status;
        let [mut a_right, mut b_right, mut c_right, mut d_right, mut e_right] = self.status;
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
        impl_md_flow!(u32 => self, message, from_le_bytes, to_le_bytes);
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
