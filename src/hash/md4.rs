use super::Hash;
use std::cmp::Ordering;

const WORD_BUFFER: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

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
    pub(crate) input: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 4],
}

impl Md4 {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            word_block: Vec::new(),
            status: WORD_BUFFER,
        }
    }
    fn padding(&mut self) {
        self.word_block = Self::md4_padding(&mut self.input);
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn round(&mut self) {
        let word_block_length = self.word_block.len() / 16;
        let (mut a, mut b, mut c, mut d);
        let mut x: [u32; 16] = [0; 16];
        for i in 0..word_block_length {
            for j in 0..16 {
                x[j] = self.word_block[16 * i + j];
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            // Round 1
            for &k in &[0, 4, 8, 12] {
                a = round1(a, b, c, d, x[k], 3);
                d = round1(d, a, b, c, x[k + 1], 7);
                c = round1(c, d, a, b, x[k + 2], 11);
                b = round1(b, c, d, a, x[k + 3], 19);
            }
            // Round 2
            for k in 0..4 {
                a = round2(a, b, c, d, x[k], 3);
                d = round2(d, a, b, c, x[k + 4], 5);
                c = round2(c, d, a, b, x[k + 8], 9);
                b = round2(b, c, d, a, x[k + 12], 13);
            }
            // Round 3
            for &k in &[0, 2, 1, 3] {
                a = round3(a, b, c, d, x[k], 3);
                d = round3(d, a, b, c, x[k + 8], 9);
                c = round3(c, d, a, b, x[k + 4], 11);
                b = round3(b, c, d, a, x[k + 12], 15);
            }
            self.status = [
                self.status[0].wrapping_add(a),
                self.status[1].wrapping_add(b),
                self.status[2].wrapping_add(c),
                self.status[3].wrapping_add(d),
            ];
        }
        for i in 0..4 {
            self.status[i] = self.status[i].swap_bytes();
        }
    }
}

impl Hash for Md4 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut md4 = Self::new();
        md4.input(input);
        md4.padding();
        md4.round();
        md4.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

// MD4と同様、又はほぼ同様のパディングを行うハッシュ関数が多いため、このような実装になっている。
pub(super) trait Md4Padding {
    fn u64_to_bytes(num: u64) -> [u8; 8];
    fn u32_from_bytes(bytes: [u8; 4]) -> u32;
    fn md4_padding(input: &mut Vec<u8>) -> Vec<u32> {
        let mut word_block = Vec::new();
        let input_length = input.len();
        // 入力末尾に0x80を追加(0b1000_0000)
        input.push(0x80);
        // [byte]: 64 - 8(input_length) - 1(0x80) = 55
        let padding_length = 55 - (input_length as i128);
        match padding_length.cmp(&0) {
            Ordering::Greater => {
                input.append(&mut vec![0; padding_length as usize]);
            }
            Ordering::Less => {
                input.append(&mut vec![0; 64 - (padding_length.abs() % 64) as usize]);
            }
            Ordering::Equal => (),
        }
        // 入力データの長さを追加
        input.append(&mut Self::u64_to_bytes(8 * input_length as u64).to_vec());
        // バイト列からワードブロックを生成
        for i in (0..input.len()).filter(|i| i % 4 == 0) {
            word_block.push(Self::u32_from_bytes([
                input[i],
                input[i + 1],
                input[i + 2],
                input[i + 3],
            ]));
        }
        word_block
    }
}

impl Md4Padding for Md4 {
    fn u64_to_bytes(num: u64) -> [u8; 8] {
        num.to_le_bytes()
    }
    fn u32_from_bytes(bytes: [u8; 4]) -> u32 {
        u32::from_le_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Md4;
    use crate::hash::Test;
    impl Test<Md4> for Md4 {}
    // https://tools.ietf.org/html/rfc1320
    const TEST_CASES: [(&[u8], &str); 10] = [
        // MD4 ("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        ("".as_bytes(), "31d6cfe0d16ae931b73c59d7e0c089c0"),
        // MD4 ("a") = bde52cb31de33e46245e05fbdbd6fb24
        ("a".as_bytes(), "bde52cb31de33e46245e05fbdbd6fb24"),
        // MD4 ("abc") = a448017aaf21d8525fc10ae87aa6729d
        ("abc".as_bytes(), "a448017aaf21d8525fc10ae87aa6729d"),
        // MD4 ("message digest") = d9130a8164549fe818874806e1c7014b
        (
            "message digest".as_bytes(),
            "d9130a8164549fe818874806e1c7014b",
        ),
        // MD4 ("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        // MD4 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 043f8582f241db351ce627e153e7f0e4
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "043f8582f241db351ce627e153e7f0e4",
        ),
        // MD4 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
        // padding_length > 0
        (&[0x30; 54], "374f6c9aa6ee2eef316d1357c4c66e73"),
        // padding_length == 0
        (&[0x30; 55], "5df3a07b1fca415a0d196e1cf255ec21"),
        // padding_length < 0
        (&[0x30; 56], "ba4591a932374808dc47c89bf7f729b3"),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Md4::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Md4::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Md4::compare_uppercase(i, e);
        }
    }
}
