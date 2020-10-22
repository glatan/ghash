use std::cmp::Ordering;
use utils::Hash;
use utils::{impl_md_flow, uint_from_bytes};

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
const fn round1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    const fn f(x: u32, y: u32, z: u32) -> u32 {
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
const fn round2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    const fn g(x: u32, y: u32, z: u32) -> u32 {
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
const fn round3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    const fn h(x: u32, y: u32, z: u32) -> u32 {
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
const fn round4(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32) -> u32 {
    const fn i(x: u32, y: u32, z: u32) -> u32 {
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
    status: [u32; 4],
}

impl Md5 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, x: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d] = self.status;

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

        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self {
            status: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
        }
    }
}

impl Hash for Md5 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32=> self, message, from_le_bytes, to_le_bytes);
        self.status[0..4]
            .iter()
            .flat_map(|byte| byte.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Md5;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 7] = [
        // https://tools.ietf.org/html/rfc1321
        ("".as_bytes(), "d41d8cd98f00b204e9800998ecf8427e"),
        ("a".as_bytes(), "0cc175b9c0f1b6a831c399e269772661"),
        ("abc".as_bytes(), "900150983cd24fb0d6963f7d28e17f72"),
        (
            "message digest".as_bytes(),
            "f96b697d7cb7938d525a2f31aaf161d0",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    impl_test!(Md5, official, OFFICIAL, Md5::default());
}
