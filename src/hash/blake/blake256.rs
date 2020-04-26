use super::{Blake, Hash, Input};

#[rustfmt::skip]
const H256: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];

pub struct Blake256(Blake<u32>);

impl Blake256 {
    pub const fn new() -> Self {
        Self(Blake::<u32> {
            message: Vec::new(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: 0,
            h: H256,
            t: [0; 2],
            v: [0; 16],
            bit: 256,
        })
    }
}

impl Input for Blake256 {
    fn input(&mut self, message: &[u8]) {
        self.0.input(message);
    }
}

impl Hash for Blake256 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut blake256 = Self::new();
        blake256.0.input(message);
        blake256.0.set_counter();
        blake256.0.padding();
        blake256.0.compress();
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
    impl Test<Blake256> for Blake256 {}
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
        for (i, e) in TEST_CASES.iter() {
            Blake256::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake256::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake256::compare_uppercase(i, e);
        }
    }
}
