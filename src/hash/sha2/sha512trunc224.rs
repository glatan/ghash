use super::{Hash, Sha2};

pub struct Sha512Trunc224(Sha2<u64>);

impl Sha512Trunc224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new([
            0x8C3D_37C8_1954_4DA2, 0x73E1_9966_89DC_D4D6, 0x1DFA_B7AE_32FF_9C82, 0x679D_D514_582F_9FCF,
            0x0F6D_2B69_7BD4_4DA8, 0x77E3_6F73_04C4_8942, 0x3F9D_85A8_6A1D_36C8, 0x1112_E6AD_91D6_92A1,
        ]))
    }
}

impl Hash for Sha512Trunc224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message);
        self.0.compress();
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .take(224 / 8) // (224 / 8) bytes
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512Trunc224;
    use crate::impl_test;

    const DEFAULT_TEST_CASES: [(&[u8], &str); 5] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
        (
            "abc".as_bytes(),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
        ),
        // padding_length > 0
        (
            &[0x30; 110],
            "2a3a18266ef16749c7e346a3179df983860eb87da02b3837f2b0aec9",
        ),
        // padding_length == 0
        (
            &[0x30; 111],
            "3e4fc8cc1265b73e7ab857d3b78d84c481d4a8d7641792f5d2d450d0",
        ),
        // padding_length < 0
        (
            &[0x30; 112],
            "7802ccf8034072805bcabc1487718da25f3894848cb43ac509b9f4b7",
        ),
    ];
    impl crate::hash::Test for Sha512Trunc224 {}
    impl_test!(
        Sha512Trunc224,
        default,
        DEFAULT_TEST_CASES,
        Sha512Trunc224::default()
    );
}
