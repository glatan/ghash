use super::{Blake, Hash, Message};

#[rustfmt::skip]
const H28: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
    0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEF_A4FA4
];

pub struct Blake28(Blake<u32>);

impl Blake28 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, H28, 224))
    }
}

impl Message for Blake28 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Blake28 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake28 = Self::new(message);
        blake28.0.padding();
        blake28.0.compress(10);
        blake28.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake28;
    use crate::hash::Test;
    impl Test for Blake28 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://ehash.iaik.tugraz.at/uploads/0/06/Blake.pdf
        (
            &[0; 1],
            "6a454fca6e347ed331d40a2f70f49a2dd4fe28761cedc5ad67c34456",
        ),
        (
            &[0; 72],
            "6ec8d4b0feaeb49450e172234c0b178e795bdc18d22420a85b6f9bb9",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake28::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake28::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake28::compare_upperhex(m, e);
        }
    }
}
