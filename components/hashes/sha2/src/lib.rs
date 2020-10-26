mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512trunc224;
mod sha512trunc256;

pub use utils::Hash;

pub use sha224::Sha224;
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use sha512trunc224::Sha512Trunc224;
pub use sha512trunc256::Sha512Trunc256;

// cargo fmtが何故か効かなくなるのでroundのように同じマクロにするのではなく、別のマクロとして定義している。
macro_rules! init_w32 {
    ($w:expr, $( $t:expr ),* ) => {
        $(
            $w[$t] = small_sigma32_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma32_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}
macro_rules! init_w64 {
    ($w:expr, $( $t:expr ),*) => {
        $(
            $w[$t] = small_sigma64_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma64_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}

macro_rules! round {
    (u32 => $t:expr, $temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr) => {
        $temp_1 = $h
            .wrapping_add(big_sigma32_1($e))
            .wrapping_add(ch32($e, $f, $g))
            .wrapping_add(K32[$t])
            .wrapping_add($w[$t]);
        $temp_2 = big_sigma32_0($a).wrapping_add(maj32($a, $b, $c));
        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add($temp_1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = $temp_1.wrapping_add($temp_2);
    };
    (u64 => $t:expr, $temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr) => {
        $temp_1 = $h
            .wrapping_add(big_sigma64_1($e))
            .wrapping_add(ch64($e, $f, $g))
            .wrapping_add(K64[$t])
            .wrapping_add($w[$t]);
        $temp_2 = big_sigma64_0($a).wrapping_add(maj64($a, $b, $c));
        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add($temp_1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = $temp_1.wrapping_add($temp_2);
    };
}

// SHA-224 and SHA-256 Constant
#[rustfmt::skip]
const K32: [u32; 64] = [
    0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0x0AB1_C5ED5,
    0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0x0C19_BF174,
    0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x076F_988DA,
    0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x0142_92967,
    0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x0927_22C85,
    0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x0106_AA070,
    0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x0682_E6FF3,
    0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0x0C67_178F2,
];
// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constant
#[rustfmt::skip]
const K64: [u64; 80] = [
    0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE, 0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725, 0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53, 0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6, 0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
];

// SHA-224 and SHA-256 Functions
const fn ch32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
const fn maj32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
const fn big_sigma32_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
const fn big_sigma32_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
const fn small_sigma32_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
const fn small_sigma32_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
const fn ch64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
const fn maj64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}
const fn big_sigma64_0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
const fn big_sigma64_1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
const fn small_sigma64_0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
const fn small_sigma64_1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

// Sha2<u32>: SHA-224 and SHA-256
// Sha2<u64>: SHA-384, SHA-512, SHA-512/224 and SHA-512/256
struct Sha2<T> {
    status: [T; 8],
}

impl Sha2<u32> {
    fn new(iv: [u32; 8]) -> Self {
        Self { status: iv }
    }
    #[inline(always)]
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        let (mut temp_1, mut temp_2);

        let mut w = [0; 64];
        w[..16].copy_from_slice(m);
        init_w32!(
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63
        );

        round!(u32 => 0, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 1, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 2, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 3, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 4, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 5, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 6, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 7, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 8, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 9, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 10, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 11, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 12, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 13, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 14, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 15, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 16, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 17, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 18, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 19, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 20, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 21, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 22, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 23, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 24, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 25, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 26, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 27, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 28, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 29, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 30, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 31, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 32, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 33, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 34, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 35, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 36, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 37, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 38, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 39, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 40, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 41, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 42, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 43, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 44, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 45, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 46, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 47, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 48, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 49, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 50, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 51, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 52, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 53, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 54, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 55, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 56, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 57, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 58, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 59, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 60, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 61, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 62, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u32 => 63, temp_1, temp_2, a, b, c, d, e, f, g, h, w);

        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
        self.status[4] = self.status[4].wrapping_add(e);
        self.status[5] = self.status[5].wrapping_add(f);
        self.status[6] = self.status[6].wrapping_add(g);
        self.status[7] = self.status[7].wrapping_add(h);
    }
}

impl Sha2<u64> {
    fn new(iv: [u64; 8]) -> Self {
        Self { status: iv }
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u64; 16]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        let (mut temp_1, mut temp_2);

        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        init_w64!(
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 77, 78, 79
        );

        round!(u64 => 0, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 1, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 2, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 3, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 4, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 5, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 6, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 7, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 8, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 9, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 10, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 11, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 12, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 13, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 14, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 15, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 16, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 17, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 18, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 19, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 20, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 21, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 22, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 23, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 24, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 25, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 26, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 27, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 28, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 29, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 30, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 31, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 32, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 33, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 34, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 35, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 36, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 37, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 38, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 39, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 40, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 41, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 42, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 43, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 44, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 45, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 46, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 47, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 48, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 49, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 50, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 51, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 52, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 53, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 54, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 55, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 56, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 57, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 58, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 59, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 60, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 61, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 62, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 63, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 64, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 65, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 66, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 67, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 68, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 69, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 70, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 71, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 72, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 73, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 74, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 75, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 76, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 77, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 78, temp_1, temp_2, a, b, c, d, e, f, g, h, w);
        round!(u64 => 79, temp_1, temp_2, a, b, c, d, e, f, g, h, w);

        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
        self.status[4] = self.status[4].wrapping_add(e);
        self.status[5] = self.status[5].wrapping_add(f);
        self.status[6] = self.status[6].wrapping_add(g);
        self.status[7] = self.status[7].wrapping_add(h);
    }
}
