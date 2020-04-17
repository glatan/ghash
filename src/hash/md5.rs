use super::Hash;
use std::cmp::Ordering;

const WORD_BUFFER: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

#[rustfmt::skip]
const T: [u32; 64] = [
    // Round 1
    0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE, 0xF57C_0FAF, 0x4787_C62A, 0xA830_4613, 0xFD46_9501,
    0x6980_98D8, 0x8B44_F7AF, 0xFFFF_5BB1, 0x895C_D7BE, 0x6B90_1122, 0xFD98_7193, 0xA679_438E, 0x49B4_0821,
    // Round 2
    0xF61E_2562, 0xC040_B340, 0x265E_5A51, 0xE9B6_C7AA, 0xD62F_105D, 0x0244_1453, 0xD8A1_E681, 0xE7D3_FBC8,
    0x21E1_CDE6, 0xC337_07D6, 0xF4D5_0D87, 0x455A_14ED, 0xA9E3_E905, 0xFCEF_A3F8, 0x676F_02D9, 0x8D2A_4C8A,
    // Round 3
    0xFFFA_3942, 0x8771_F681, 0x6D9D_6122, 0xFDE5_380C, 0xA4BE_EA44, 0x4BDE_CFA9, 0xF6BB_4B60, 0xBEBF_BC70,
    0x289B_7EC6, 0xEAA1_27FA, 0xD4EF_3085, 0x0488_1D05, 0xD9D4_D039, 0xE6DB_99E5, 0x1FA2_7CF8, 0xC4AC_5665,
    // Round 4
    0xF429_2244, 0x432A_FF97, 0xAB94_23A7, 0xFC93_A039, 0x655B_59C3, 0x8F0C_CC92, 0xFFEF_F47D, 0x8584_5DD1,
    0x6FA8_7E4F, 0xFE2C_E6E0, 0xA301_4314, 0x4E08_11A1, 0xF753_7E82, 0xBD3A_F235, 0x2AD7_D2BB, 0xEB86_D391,
];

#[allow(clippy::many_single_char_names)]
fn round1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    b.wrapping_add(
        a.wrapping_add(f(b, c, d))
            .wrapping_add(k)
            .wrapping_add(t)
            .rotate_left(s),
    )
}

#[allow(clippy::many_single_char_names)]
fn round2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }
    b.wrapping_add(
        a.wrapping_add(g(b, c, d))
            .wrapping_add(k)
            .wrapping_add(t)
            .rotate_left(s),
    )
}

#[allow(clippy::many_single_char_names)]
fn round3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    b.wrapping_add(
        a.wrapping_add(h(b, c, d))
            .wrapping_add(k)
            .wrapping_add(t)
            .rotate_left(s),
    )
}

#[allow(clippy::many_single_char_names)]
fn round4(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    fn i(x: u32, y: u32, z: u32) -> u32 {
        y ^ (x | !z)
    }
    b.wrapping_add(
        a.wrapping_add(i(b, c, d))
            .wrapping_add(k)
            .wrapping_add(t)
            .rotate_left(s),
    )
}

pub struct Md5 {
    input: Vec<u8>,
    word_block: Vec<u32>,
    status: [u32; 4],
}

impl Md5 {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            word_block: Vec::new(),
            status: WORD_BUFFER,
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
            .append(&mut (8 * input_length as u64).to_le_bytes().to_vec());
        // iは4の倍数となる (0, 4, 8..60..)
        for i in (0..self.input.len()).filter(|i| i % 4 == 0) {
            self.word_block.push(u32::from_le_bytes([
                self.input[i],
                self.input[i + 1],
                self.input[i + 2],
                self.input[i + 3],
            ]));
        }
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
            a = round1(a, b, c, d, x[0], 7, T[0]);
            d = round1(d, a, b, c, x[1], 12, T[1]);
            c = round1(c, d, a, b, x[2], 17, T[2]);
            b = round1(b, c, d, a, x[3], 22, T[3]);
            a = round1(a, b, c, d, x[4], 7, T[4]);
            d = round1(d, a, b, c, x[5], 12, T[5]);
            c = round1(c, d, a, b, x[6], 17, T[6]);
            b = round1(b, c, d, a, x[7], 22, T[7]);
            a = round1(a, b, c, d, x[8], 7, T[8]);
            d = round1(d, a, b, c, x[9], 12, T[9]);
            c = round1(c, d, a, b, x[10], 17, T[10]);
            b = round1(b, c, d, a, x[11], 22, T[11]);
            a = round1(a, b, c, d, x[12], 7, T[12]);
            d = round1(d, a, b, c, x[13], 12, T[13]);
            c = round1(c, d, a, b, x[14], 17, T[14]);
            b = round1(b, c, d, a, x[15], 22, T[15]);
            // Round 2
            a = round2(a, b, c, d, x[1], 5, T[16]);
            d = round2(d, a, b, c, x[6], 9, T[17]);
            c = round2(c, d, a, b, x[11], 14, T[18]);
            b = round2(b, c, d, a, x[0], 20, T[19]);
            a = round2(a, b, c, d, x[5], 5, T[20]);
            d = round2(d, a, b, c, x[10], 9, T[21]);
            c = round2(c, d, a, b, x[15], 14, T[22]);
            b = round2(b, c, d, a, x[4], 20, T[23]);
            a = round2(a, b, c, d, x[9], 5, T[24]);
            d = round2(d, a, b, c, x[14], 9, T[25]);
            c = round2(c, d, a, b, x[3], 14, T[26]);
            b = round2(b, c, d, a, x[8], 20, T[27]);
            a = round2(a, b, c, d, x[13], 5, T[28]);
            d = round2(d, a, b, c, x[2], 9, T[29]);
            c = round2(c, d, a, b, x[7], 14, T[30]);
            b = round2(b, c, d, a, x[12], 20, T[31]);
            // Round 3
            a = round3(a, b, c, d, x[5], 4, T[32]);
            d = round3(d, a, b, c, x[8], 11, T[33]);
            c = round3(c, d, a, b, x[11], 16, T[34]);
            b = round3(b, c, d, a, x[14], 23, T[35]);
            a = round3(a, b, c, d, x[1], 4, T[36]);
            d = round3(d, a, b, c, x[4], 11, T[37]);
            c = round3(c, d, a, b, x[7], 16, T[38]);
            b = round3(b, c, d, a, x[10], 23, T[39]);
            a = round3(a, b, c, d, x[13], 4, T[40]);
            d = round3(d, a, b, c, x[0], 11, T[41]);
            c = round3(c, d, a, b, x[3], 16, T[42]);
            b = round3(b, c, d, a, x[6], 23, T[43]);
            a = round3(a, b, c, d, x[9], 4, T[44]);
            d = round3(d, a, b, c, x[12], 11, T[45]);
            c = round3(c, d, a, b, x[15], 16, T[46]);
            b = round3(b, c, d, a, x[2], 23, T[47]);
            // Round 4
            a = round4(a, b, c, d, x[0], 6, T[48]);
            d = round4(d, a, b, c, x[7], 10, T[49]);
            c = round4(c, d, a, b, x[14], 15, T[50]);
            b = round4(b, c, d, a, x[5], 21, T[51]);
            a = round4(a, b, c, d, x[12], 6, T[52]);
            d = round4(d, a, b, c, x[3], 10, T[53]);
            c = round4(c, d, a, b, x[10], 15, T[54]);
            b = round4(b, c, d, a, x[1], 21, T[55]);
            a = round4(a, b, c, d, x[8], 6, T[56]);
            d = round4(d, a, b, c, x[15], 10, T[57]);
            c = round4(c, d, a, b, x[6], 15, T[58]);
            b = round4(b, c, d, a, x[13], 21, T[59]);
            a = round4(a, b, c, d, x[4], 6, T[60]);
            d = round4(d, a, b, c, x[11], 10, T[61]);
            c = round4(c, d, a, b, x[2], 15, T[62]);
            b = round4(b, c, d, a, x[9], 21, T[63]);
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

impl Hash for Md5 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut md5 = Self::new();
        md5.input = input.to_vec();
        md5.padding();
        md5.round();
        md5.status[0..4]
            .iter()
            .flat_map(|byte| byte.to_be_bytes().to_vec())
            .collect()
    }
}