use super::{Blake, Hash};

#[rustfmt::skip]
const H224: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
    0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEF_A4FA4
];

pub struct Blake224(Blake<u32>);

impl Blake224 {
    pub const fn new() -> Self {
        Self(Blake::<u32> {
            input: Vec::new(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: 0,
            h: H224,
            t: [0; 2],
            v: [0; 16],
            bit: 224,
        })
    }
    fn padding(&mut self) {
        self.0.padding();
    }
    fn compress(&mut self) {
        self.0.compress();
    }
}

impl Hash for Blake224 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut blake224 = Self::new();
        blake224.0.input(input);
        blake224.padding();
        blake224.compress();
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
    impl Test<Blake224> for Blake224 {}
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
        for (i, e) in TEST_CASES.iter() {
            Blake224::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake224::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake224::compare_uppercase(i, e);
        }
    }
}
