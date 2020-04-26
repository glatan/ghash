use super::Hash;
use crate::impl_md4_padding;
use std::cmp::Ordering;

// K(t) = 5A827999 ( 0 <= t <= 19)
// K(t) = 6ED9EBA1 (20 <= t <= 39)
// K(t) = 8F1BBCDC (40 <= t <= 59)
// K(t) = CA62C1D6 (60 <= t <= 79)
const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

const H: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

// 0 <= t <= 19
const fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

// 20 <= t <= 39, 60 <= t <= 79
const fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

// 40 <= t <= 59
const fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

pub struct Sha1 {
    pub(super) message: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 5],
}

impl Sha1 {
    // Padding
    impl_md4_padding!(u32 => self, from_be_bytes, to_be_bytes, 55, {});
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            message: Vec::new(),
            word_block: Vec::new(),
            status: H,
        }
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn round(&mut self) {
        let (mut a, mut b, mut c, mut d, mut e);
        let mut temp;
        let mut w = [0; 80];
        for i in 0..(self.word_block.len() / 16) {
            for t in 0..16 {
                w[t] = self.word_block[t + i * 16];
            }
            for t in 16..80 {
                w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            e = self.status[4];
            // 0 <= t <= 19
            for wt in w.iter().take(20) {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(ch(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(*wt)
                    .wrapping_add(K[0]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 20 <= t <= 39
            for wt in w.iter().take(40).skip(20) {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(*wt)
                    .wrapping_add(K[1]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 40 <= t <= 59
            for wt in w.iter().take(60).skip(40) {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(maj(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(*wt)
                    .wrapping_add(K[2]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 60 <= t <= 79
            for wt in w.iter().skip(60) {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(*wt)
                    .wrapping_add(K[3]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            self.status[0] = self.status[0].wrapping_add(a);
            self.status[1] = self.status[1].wrapping_add(b);
            self.status[2] = self.status[2].wrapping_add(c);
            self.status[3] = self.status[3].wrapping_add(d);
            self.status[4] = self.status[4].wrapping_add(e);
        }
    }
}

impl Hash for Sha1 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut sha1 = Self::new();
        sha1.input(message);
        sha1.padding();
        sha1.round();
        sha1.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1;
    use crate::hash::Test;
    impl Test<Sha1> for Sha1 {}
    // https://tools.ietf.org/html/rfc3174
    const TEST_CASES: [(&[u8], &str); 7] = [
        // SHA1 ("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        ("abc".as_bytes(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
        // SHA1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        // SHA1 ("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
        ("a".as_bytes(), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
        // SHA1 ("0123456701234567012345670123456701234567012345670123456701234567") = e0c094e867ef46c350ef54a7f59dd60bed92ae83
        (
            "0123456701234567012345670123456701234567012345670123456701234567".as_bytes(),
            "e0c094e867ef46c350ef54a7f59dd60bed92ae83",
        ),
        // padding_length > 0
        (&[0x30; 54], "fcd2740438dd7a05dc5747d176fd65dda58cfd01"),
        // padding_length == 0
        (&[0x30; 55], "8fffd3df3d041baf53b27f42ec802cfb362710bd"),
        // padding_length < 0
        (&[0x30; 56], "2a04b5125ba4030ef13232ecf1b72849f6ec9e97"),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Sha1::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha1::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha1::compare_uppercase(i, e);
        }
    }
}
