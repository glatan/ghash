use super::{Hash, Sha2_64bit};

#[rustfmt::skip]
pub const H512_TRUNC_224: [u64; 8] = [
    0x8C3D_37C8_1954_4DA2, 0x73E1_9966_89DC_D4D6, 0x1DFA_B7AE_32FF_9C82, 0x679D_D514_582F_9FCF,
    0x0F6D_2B69_7BD4_4DA8, 0x77E3_6F73_04C4_8942, 0x3F9D_85A8_6A1D_36C8, 0x1112_E6AD_91D6_92A1,
];

pub struct Sha512Trunc224(Sha2_64bit);

impl Sha512Trunc224 {
    pub const fn new() -> Self {
        Self(Sha2_64bit {
            input: Vec::new(),
            word_block: Vec::new(),
            status: H512_TRUNC_224,
        })
    }
    fn padding(&mut self) {
        self.0.padding();
    }
    fn round(&mut self) {
        self.0.round();
    }
}

impl Hash for Sha512Trunc224 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut sha512trunc224 = Self::new();
        sha512trunc224.0.input = input.to_vec();
        sha512trunc224.padding();
        sha512trunc224.round();
        sha512trunc224.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .take(224 / 8) // (224 / 8) bytes
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::Sha512Trunc224;
    use crate::hash::Test;
    impl Test<Sha512Trunc224> for Sha512Trunc224 {}
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
    const TEST_CASES: [(&[u8], &str); 2] = [
        // SHA-512/224("abc") = 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
        (
            "abc".as_bytes(),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        // SHA-512/224("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
        ),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Sha512Trunc224::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha512Trunc224::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha512Trunc224::compare_uppercase(i, e);
        }
    }
}
