use super::Hash;
use crate::impl_padding;
use std::cmp::Ordering;

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
    word_block: Vec<u32>,
    status: [u32; 4],
}

impl Md5 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self) {
        let (mut a, mut b, mut c, mut d);
        let mut x: [u32; 16] = [0; 16];
        for i in 0..(self.word_block.len() / 16) {
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
        self.status[0] = self.status[0].swap_bytes();
        self.status[1] = self.status[1].swap_bytes();
        self.status[2] = self.status[2].swap_bytes();
        self.status[3] = self.status[3].swap_bytes();
    }
}

impl Md5 {
    impl_padding!(u32 => self, from_le_bytes, to_le_bytes);
}

impl Default for Md5 {
    fn default() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
        }
    }
}

impl Hash for Md5 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.padding(message);
        self.compress();
        self.status[0..4]
            .iter()
            .flat_map(|byte| byte.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Md5;
    use crate::impl_test;

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
    const ZERO_FILL: [(&[u8], &str); 128] = [
        // Generated by using the official implementation(https://tools.ietf.org/html/rfc1321)
        // Replaced UINT4 to uint32_t and unsigned char to uint8_t
        (&[0; 0], "d41d8cd98f00b204e9800998ecf8427e"),
        (&[0; 1], "93b885adfe0da089cdf634904fd59f71"),
        (&[0; 2], "c4103f122d27677c9db144cae1394a66"),
        (&[0; 3], "693e9af84d3dfcc71e640e005bdc5e2e"),
        (&[0; 4], "f1d3ff8443297732862df21dc4e57262"),
        (&[0; 5], "ca9c491ac66b2c62500882e93f3719a8"),
        (&[0; 6], "7319468847d7b1aee40dbf5dd963c999"),
        (&[0; 7], "d310a40483f9399dd7ed1712e0fdd702"),
        (&[0; 8], "7dea362b3fac8e00956a4952a3d4f474"),
        (&[0; 9], "3f2829b2ffe8434d67f98a2a98968652"),
        (&[0; 10], "a63c90cc3684ad8b0a2176a6a8fe9005"),
        (&[0; 11], "74da4121dc1c0ed2a8e5b0741f824034"),
        (&[0; 12], "8dd6bb7329a71449b0a1b292b5999164"),
        (&[0; 13], "0b867e53c1d233ce9fe49d54549a2323"),
        (&[0; 14], "36df9540a5ef4996a9737657e4a8929c"),
        (&[0; 15], "3449c9e5e332f1dbb81505cd739fbf3f"),
        (&[0; 16], "4ae71336e44bf9bf79d2752e234818a5"),
        (&[0; 17], "f3c8bdb6b9df478f227af2ce61c8a5a1"),
        (&[0; 18], "ff035bff2dcf972ee7dfd023455997ef"),
        (&[0; 19], "0e6bce6899fae841f79024afbdf7db1d"),
        (&[0; 20], "441018525208457705bf09a8ee3c1093"),
        (&[0; 21], "2319ac34f4848755a639fd524038dfd3"),
        (&[0; 22], "db46e81649d6863b16bd99ab139c865b"),
        (&[0; 23], "6b43b583e2b662724b6fbb5189f6ab28"),
        (&[0; 24], "1681ffc6e046c7af98c9e6c232a3fe0a"),
        (&[0; 25], "d28c293e10139d5d8f6e4592aeaffc1b"),
        (&[0; 26], "a396c59a96af3b36d364448c7b687fb1"),
        (&[0; 27], "65435a5d117aa6b052a5f737d9946a7b"),
        (&[0; 28], "1c9e99e48a495fe81d388fdb4900e59f"),
        (&[0; 29], "4aa476a72347ba44c9bd20c974d0f181"),
        (&[0; 30], "862dec5c27142824a394bc6464928f48"),
        (&[0; 31], "3861facee9efc127e340387f1936b8fb"),
        (&[0; 32], "70bc8f4b72a86921468bf8e8441dce51"),
        (&[0; 33], "099a150e83972a433492a59c2fbe98e0"),
        (&[0; 34], "0b91f1d54f932dc6382dc69f197900cf"),
        (&[0; 35], "c54104d7894a1941ca710981da437f9f"),
        (&[0; 36], "81684c2e68ade2cd4bf9f2e8a67dd4fe"),
        (&[0; 37], "21e2e8fe686ed0003b67d698b1273481"),
        (&[0; 38], "f3a534d52e3fe0c7a85b30ca00ca7424"),
        (&[0; 39], "002d5910de023eddce8358edf169c07f"),
        (&[0; 40], "fd4b38e94292e00251b9f39c47ee5710"),
        (&[0; 41], "f5cfd73023c1eedb6b9569736073f1dd"),
        (&[0; 42], "c183857770364b05c2011bdebb914ed3"),
        (&[0; 43], "aea2fa668453e23c431649801e5ea548"),
        (&[0; 44], "3e5ceb07f51a70d9d431714f04c0272f"),
        (&[0; 45], "7622214b8536afe7b89b1c6606069b0d"),
        (&[0; 46], "d898504a722bff1524134c6ab6a5eaa5"),
        (&[0; 47], "0d7db7ff842f89a36b58fa2541de2a6c"),
        (&[0; 48], "b203621a65475445e6fcdca717c667b5"),
        (&[0; 49], "884bb48a55da67b4812805cb8905277d"),
        (&[0; 50], "871bdd96b159c14d15c8d97d9111e9c8"),
        (&[0; 51], "e2365bc6a6fbd41287fae648437296fa"),
        (&[0; 52], "469aa816010c9c8639a9176f625189af"),
        (&[0; 53], "eca0470178275ac94e5de381969ed232"),
        (&[0; 54], "8910e6fc12f07a52b796eb55fbf3edda"),
        (&[0; 55], "c9ea3314b91c9fd4e38f9432064fd1f2"),
        (&[0; 56], "e3c4dd21a9171fd39d208efa09bf7883"),
        (&[0; 57], "ab9d8ef2ffa9145d6c325cefa41d5d4e"),
        (&[0; 58], "2c1cf4f76fa1cecc0c4737cfd8d95118"),
        (&[0; 59], "22031453e4c3a1a0d47b0b97d83d8984"),
        (&[0; 60], "a302a771ee0e3127b8950f0a67d17e49"),
        (&[0; 61], "e2a482a3896964675811dba0bfde2f0b"),
        (&[0; 62], "8d7d1020185f9b09cc22e789887be328"),
        (&[0; 63], "65cecfb980d72fde57d175d6ec1c3f64"),
        (&[0; 64], "3b5d3c7d207e37dceeedd301e35e2e58"),
        (&[0; 65], "1ef5e829303a139ce967440e0cdca10c"),
        (&[0; 66], "402535c9f22ff836ea91dd12e8b8847b"),
        (&[0; 67], "53553242d57214aaa5726a09b05fe7bc"),
        (&[0; 68], "7c909b3e2820c8b47ed418753698a6da"),
        (&[0; 69], "3b8151acfb469ae41d3f0449058076e1"),
        (&[0; 70], "3287282fa1a1523a294fb018e3679872"),
        (&[0; 71], "2f0f98115f17f2869c1f59ba804af077"),
        (&[0; 72], "ac3b5a19643ee5816a1df17f2fadaae3"),
        (&[0; 73], "fa67ab9184f8d574cef7cd8e0b2f1a78"),
        (&[0; 74], "aa6672fe9e8426f8dd570c81095e1476"),
        (&[0; 75], "6e36ba0fe61f7c6334305d61299c04cf"),
        (&[0; 76], "e6b62b76fb2eb2a0e0adde0c067da680"),
        (&[0; 77], "2b62a30906a2b8bf3b68abd2ef9d105b"),
        (&[0; 78], "b79abf5c5f2244956c7246e9112595ce"),
        (&[0; 79], "55712f2f2f21a8321b9ee45d40b89091"),
        (&[0; 80], "bbf7c6077962a7c28114dbd10be947cd"),
        (&[0; 81], "9546c10433c45bfb9947449dd8d304de"),
        (&[0; 82], "516c0567e329930b320357809a0c9149"),
        (&[0; 83], "0efce63cf4c085888a2772125dfe7aaa"),
        (&[0; 84], "3561c0dffdb90248fa1fc2d4fb86f08a"),
        (&[0; 85], "eeb20c9bc165677800b6dc7621a50cc9"),
        (&[0; 86], "bb1ef3ddda35b590d4aa204d0493e921"),
        (&[0; 87], "eecae68e4f9ee6f037742aac8f36cc1b"),
        (&[0; 88], "f2331152449c622545360f18dfdf0e2d"),
        (&[0; 89], "335a7c8e767a2dd0ecf3460eaabb0bbd"),
        (&[0; 90], "3277ca99dfe4a704df82c63ac9e876fd"),
        (&[0; 91], "67130d31b6048171a64ed87d36022a6e"),
        (&[0; 92], "534d78034b774b6266f2189576f8c6e3"),
        (&[0; 93], "90c805bcb9fa376aacfb38d598ec7bb6"),
        (&[0; 94], "363c2e67f9e853fbc532d0b6404db30a"),
        (&[0; 95], "0a1dfc18c8c8381f05f8ad9d2b4509b5"),
        (&[0; 96], "aceb486e7e4b2d2f1c5f2328b503502b"),
        (&[0; 97], "9e0573ecb4a0800788a3aa64ad731bbc"),
        (&[0; 98], "33aa8cb471ba9dee750c069bca801127"),
        (&[0; 99], "fa8715078d45101200a6e2bf7321aa04"),
        (&[0; 100], "6d0bb00954ceb7fbee436bb55a8397a9"),
        (&[0; 101], "22577911e88af39f79409e6de8eed4d9"),
        (&[0; 102], "f5e502b5576c2ceb07f0f03afdede1f7"),
        (&[0; 103], "213e635dac590095b5681a944a5713a2"),
        (&[0; 104], "3189de1ff1f8afed0f70e352dfcd2abb"),
        (&[0; 105], "d1950d80f172e80f1c48685c51835807"),
        (&[0; 106], "f536fbf78e26387affb82ee89943b870"),
        (&[0; 107], "eaf25f841c19e96c5ad6217e6286e28b"),
        (&[0; 108], "60c6b126049a35e50fffeadf17279275"),
        (&[0; 109], "aa9ecdc8d4e3ecddb3cdc851ea2eeb61"),
        (&[0; 110], "faee174ece449bca53aea3129d925069"),
        (&[0; 111], "03bc63b77bec853adcb65719a21459ce"),
        (&[0; 112], "c20019258ca235d2408334dfbc5e67e3"),
        (&[0; 113], "b9205d5c0a413e022f6c36d4bdfa0750"),
        (&[0; 114], "301657e2669b4c76979a15f801cc2adf"),
        (&[0; 115], "39dbf807a41e5e4e63b59c9535c72eb7"),
        (&[0; 116], "617f292bebf954b26d56f326b51c8a82"),
        (&[0; 117], "b5d466335d65b171b686700dee05ef74"),
        (&[0; 118], "1a6bf84723f4e07dc1f35f162acec19b"),
        (&[0; 119], "8271cb2e6a546123b43096a2efce39d2"),
        (&[0; 120], "222f7d881ded1871724a1b9a1cb94247"),
        (&[0; 121], "709c6a80af0276b170c521117ede47c6"),
        (&[0; 122], "b7d01d15f7334eed7ea235515822f7d5"),
        (&[0; 123], "b1fec41621e338896e2d26f232a6b006"),
        (&[0; 124], "3aaceebd65f0b79f9ae1718d3241bf37"),
        (&[0; 125], "38397588c4d02f8b95c263852e9aee7a"),
        (&[0; 126], "91492f3350f4a1c513741f6aa8a96b5a"),
        (&[0; 127], "e457fbae1dd166a0c89d244ac03f4e93"),
    ];
    impl_test!(Md5, official, OFFICIAL, Md5::default());
    impl_test!(Md5, zero_fill, ZERO_FILL, Md5::default());
}
