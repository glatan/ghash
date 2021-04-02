#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use utils::Hash;

#[cfg(feature = "minimal")]
use utils::impl_md_flow_minimal;
#[cfg(not(feature = "minimal"))]
use utils::{impl_md_flow, uint_from_bytes};

#[allow(clippy::many_single_char_names)]
const fn round1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
}

#[allow(clippy::many_single_char_names)]
const fn round2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    a.wrapping_add(g(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x5A82_7999)
        .rotate_left(s)
}

#[allow(clippy::many_single_char_names)]
const fn round3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    a.wrapping_add(h(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x6ED9_EBA1)
        .rotate_left(s)
}

pub struct Md4 {
    status: [u32; 4],
}

impl Md4 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names)]
    fn compress(&mut self, x: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d] = self.status;

        a = round1(a, b, c, d, x[0], 3);
        d = round1(d, a, b, c, x[1], 7);
        c = round1(c, d, a, b, x[2], 11);
        b = round1(b, c, d, a, x[3], 19);
        a = round1(a, b, c, d, x[4], 3);
        d = round1(d, a, b, c, x[5], 7);
        c = round1(c, d, a, b, x[6], 11);
        b = round1(b, c, d, a, x[7], 19);
        a = round1(a, b, c, d, x[8], 3);
        d = round1(d, a, b, c, x[9], 7);
        c = round1(c, d, a, b, x[10], 11);
        b = round1(b, c, d, a, x[11], 19);
        a = round1(a, b, c, d, x[12], 3);
        d = round1(d, a, b, c, x[13], 7);
        c = round1(c, d, a, b, x[14], 11);
        b = round1(b, c, d, a, x[15], 19);

        a = round2(a, b, c, d, x[0], 3);
        d = round2(d, a, b, c, x[4], 5);
        c = round2(c, d, a, b, x[8], 9);
        b = round2(b, c, d, a, x[12], 13);
        a = round2(a, b, c, d, x[1], 3);
        d = round2(d, a, b, c, x[5], 5);
        c = round2(c, d, a, b, x[9], 9);
        b = round2(b, c, d, a, x[13], 13);
        a = round2(a, b, c, d, x[2], 3);
        d = round2(d, a, b, c, x[6], 5);
        c = round2(c, d, a, b, x[10], 9);
        b = round2(b, c, d, a, x[14], 13);
        a = round2(a, b, c, d, x[3], 3);
        d = round2(d, a, b, c, x[7], 5);
        c = round2(c, d, a, b, x[11], 9);
        b = round2(b, c, d, a, x[15], 13);

        a = round3(a, b, c, d, x[0], 3);
        d = round3(d, a, b, c, x[8], 9);
        c = round3(c, d, a, b, x[4], 11);
        b = round3(b, c, d, a, x[12], 15);
        a = round3(a, b, c, d, x[2], 3);
        d = round3(d, a, b, c, x[10], 9);
        c = round3(c, d, a, b, x[6], 11);
        b = round3(b, c, d, a, x[14], 15);
        a = round3(a, b, c, d, x[1], 3);
        d = round3(d, a, b, c, x[9], 9);
        c = round3(c, d, a, b, x[5], 11);
        b = round3(b, c, d, a, x[13], 15);
        a = round3(a, b, c, d, x[3], 3);
        d = round3(d, a, b, c, x[11], 9);
        c = round3(c, d, a, b, x[7], 11);
        b = round3(b, c, d, a, x[15], 15);

        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
    }
}

impl Default for Md4 {
    fn default() -> Self {
        Self {
            status: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
        }
    }
}

impl Hash for Md4 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        #[cfg(feature = "minimal")]
        impl_md_flow_minimal!(u32=> self, message, from_le_bytes, to_le_bytes);
        #[cfg(not(feature = "minimal"))]
        impl_md_flow!(u32=> self, message, from_le_bytes, to_le_bytes);
        self.status[0..4]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Md4;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 7] = [
        // https://tools.ietf.org/html/rfc1320
        ("".as_bytes(), "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a".as_bytes(), "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc".as_bytes(), "a448017aaf21d8525fc10ae87aa6729d"),
        (
            "message digest".as_bytes(),
            "d9130a8164549fe818874806e1c7014b",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ];
    impl_test!(Md4, md4_official, OFFICIAL, Md4::default());
}
