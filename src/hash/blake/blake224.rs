use super::{Blake, Hash, Message};

#[rustfmt::skip]
const H224: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
    0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEF_A4FA4
];

pub struct Blake224(Blake<u32>);

impl Blake224 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, H224, 224))
    }
}

impl Message for Blake224 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Blake224 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake224 = Self::new(message);
        blake224.0.padding();
        blake224.0.compress(14);
        blake224.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake224;
    use crate::hash::Test;
    impl Test for Blake224 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://131002.net/blake/blake.pdf
        (
            &[0; 1],
            "4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5",
        ),
        (
            &[0; 72],
            "f5aa00dd1cb847e3140372af7b5c46b4888d82c8c0a917913cfb5d04",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_upperhex(m, e);
        }
    }
}
