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

pub struct Sha0 {
    word_block: Vec<u32>,
    status: [u32; 5],
}

impl Sha0 {
    fn new() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: H,
        }
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self) {
        let (mut a, mut b, mut c, mut d, mut e);
        let mut temp;
        let mut w = [0; 80];
        for i in 0..(self.word_block.len() / 16) {
            for t in 0..16 {
                w[t] = self.word_block[t + i * 16];
            }
            for t in 16..80 {
                w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            e = self.status[4];
            // 0 <= t <= 19
            for t in 0..20 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(ch(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[0]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 20 <= t <= 39
            for t in 20..40 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[1]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 40 <= t <= 59
            for t in 40..60 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(maj(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[2]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            // 60 <= t <= 79
            for t in 60..80 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
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

impl Sha0 {
    // Padding
    impl_md4_padding!(u32 => self, from_be_bytes, to_be_bytes);
}

impl Hash for Sha0 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut sha0 = Self::new();
        sha0.padding(message);
        sha0.compress();
        sha0.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha0;
    use crate::hash::Test;
    impl Test for Sha0 {}
    // https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
    // https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
    const TEST_CASES: [(&[u8], &str); 5] = [
        // SHA0 ("abc") = 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        ("abc".as_bytes(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        // SHA0 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = d2516ee1acfa5baf33dfc1c471e438449ef134c8
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
        ),
        // padding_length > 0
        (&[0x30; 54], "bea111dd3c7b0b30372a6c85c149eab680c9de9f"),
        // padding_length == 0
        (&[0x30; 55], "6b486fba8c9d3c8ba45c10990df5b579f4244235"),
        // padding_length < 0
        (&[0x30; 56], "09b8542ca835eaeaf90fd80f0fe59b061fddadee"),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Sha0::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Sha0::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Sha0::compare_upperhex(m, e);
        }
    }
}
