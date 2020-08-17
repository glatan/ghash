use super::{Blake, Hash, Message};

#[rustfmt::skip]
const IV256: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];

pub struct Blake256(Blake<u32>);

impl Blake256 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, IV256, 256))
    }
}

impl Message for Blake256 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Blake256 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake256 = Self::new(message);
        blake256.0.padding();
        blake256.0.compress(14);
        blake256
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake256;
    use crate::hash::Test;
    impl Test for Blake256 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://131002.net/blake/blake.pdf
        (
            &[0; 1],
            "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87",
        ),
        (
            &[0; 72],
            "d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_upperhex(m, e);
        }
    }
}
