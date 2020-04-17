use super::Hash;
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
fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

// 20 <= t <= 39, 60 <= t <= 79
fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

// 40 <= t <= 59
fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

pub struct Sha0 {
    input: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 5],
}

impl Sha0 {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            word_block: Vec::new(),
            status: H,
        }
    }
    fn padding(&mut self) {
        let input_length = self.input.len();
        // word_block末尾に0x80を追加(0b1000_0000)
        self.input.push(0x80);
        // (self.word_block.len() % 64)が55(56 - 1)になるよう0を追加する数
        let padding_length = 55 - (input_length as isize % 64);
        match padding_length.cmp(&0) {
            Ordering::Greater => {
                self.input.append(&mut vec![0; padding_length as usize]);
            }
            Ordering::Less => {
                self.input
                    .append(&mut vec![0; (padding_length + 64) as usize]);
            }
            Ordering::Equal => {
                self.input.append(&mut vec![0; 64]);
            }
        }
        // 入力データの長さを追加
        self.input
            .append(&mut (8 * input_length as u64).to_be_bytes().to_vec());
        // iは4の倍数となる (0, 4, 8..60..)
        for i in (0..self.input.len()).filter(|i| i % 4 == 0) {
            self.word_block.push(u32::from_be_bytes([
                self.input[i],
                self.input[i + 1],
                self.input[i + 2],
                self.input[i + 3],
            ]));
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
                w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
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

impl Hash for Sha0 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut sha0 = Self::new();
        sha0.input = input.to_vec();
        sha0.padding();
        sha0.round();
        sha0.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::super::Test;
    use super::Sha0;
    impl Test<Sha0> for Sha0 {}
    // https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
    // https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
    const TEST_CASES: [(&[u8], &str); 2] = [
        // SHA0 ("abc") = 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        ("abc".as_bytes(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        // SHA0 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = d2516ee1acfa5baf33dfc1c471e438449ef134c8
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
        ),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Sha0::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha0::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha0::compare_uppercase(i, e);
        }
    }
}
