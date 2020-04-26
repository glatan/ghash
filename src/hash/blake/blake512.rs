use super::{Blake, Hash, Message};

#[rustfmt::skip]
const H512: [u64; 8] = [
    0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
];

pub struct Blake512(Blake<u64>);

impl Blake512 {
    pub const fn new() -> Self {
        Self(Blake::<u64> {
            message: Vec::new(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: 0,
            h: H512,
            t: [0; 2],
            v: [0; 16],
            bit: 512,
        })
    }
}

impl Message for Blake512 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Blake512 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut blake512 = Self::new();
        blake512.0.message(message);
        blake512.0.set_counter();
        blake512.0.padding();
        blake512.0.compress();
        blake512
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake512;
    use crate::hash::Test;
    impl Test for Blake512 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://131002.net/blake/blake.pdf
        (
            &[0; 1],
            "97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3",
        ),
        (
            &[0; 144],
            "313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde",
        ),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Blake512::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake512::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake512::compare_uppercase(i, e);
        }
    }
}
