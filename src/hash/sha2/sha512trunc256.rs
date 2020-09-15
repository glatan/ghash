use super::{Hash, Sha2};

pub struct Sha512Trunc256(Sha2<u64>);

impl Sha512Trunc256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new([
            0x2231_2194_FC2B_F72C, 0x9F55_5FA3_C84C_64C2, 0x2393_B86B_6F53_B151, 0x9638_7719_5940_EABD,
            0x9628_3EE2_A88E_FFE3, 0xBE5E_1E25_5386_3992, 0x2B01_99FC_2C85_B8AA, 0x0EB7_2DDC_81C5_2CA2,
        ]))
    }
}

impl Hash for Sha512Trunc256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message);
        self.0.compress();
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
const DEFAULT_TEST_CASES: [(&[u8], &str); 5] = [
    // SHA-512/256("abc") = 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
    (
        "abc".as_bytes(),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    ),
    // SHA-512/256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a
    (
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    ),
    // padding_length > 0
    (
        &[0x30; 110],
        "3354c515c767ac237437d3a311ad7f358357b262c0260507f2906ee971a33e3d",
    ),
    // padding_length == 0
    (
        &[0x30; 111],
        "c9a229d5e090a803310becdeddb7ad0070b2c87b21d2bdef5ccfe775e27a7f23",
    ),
    // padding_length < 0
    (
        &[0x30; 112],
        "9a20cd139b1c0a0212362bffdc25230b1f87c0fb24651957febce335818d197e",
    ),
];

#[cfg(test)]
impl crate::hash::Test for Sha512Trunc256 {}
#[cfg(test)]
impl_test!(
    Sha512Trunc256,
    default,
    DEFAULT_TEST_CASES,
    Sha512Trunc256::default()
);
