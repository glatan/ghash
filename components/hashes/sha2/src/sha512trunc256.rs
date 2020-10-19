use super::Sha2;
use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

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
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512Trunc256;
    use utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
        (
            "abc".as_bytes(),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
        ),
    ];
    impl_test!(
        Sha512Trunc256,
        official,
        OFFICIAL,
        Sha512Trunc256::default()
    );
}
