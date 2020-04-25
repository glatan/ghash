use super::{Blake, Hash};

#[rustfmt::skip]
const H384: [u64; 8] = [
    0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
    0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
];

pub struct Blake384(Blake<u64>);

impl Blake384 {
    pub const fn new() -> Self {
        Self(Blake::<u64> {
            input: Vec::new(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: 0,
            h: H384,
            t: [0; 2],
            v: [0; 16],
            bit: 384,
        })
    }
    fn padding(&mut self) {
        self.0.padding();
    }
    fn compress(&mut self) {
        self.0.compress();
    }
}

impl Hash for Blake384 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut blake384 = Self::new();
        blake384.0.input(input);
        blake384.padding();
        blake384.compress();
        blake384.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake384;
    use crate::hash::Test;
    impl Test<Blake384> for Blake384 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://131002.net/blake/blake.pdf
        (
            &[0; 1],
            "10281f67e135e90ae8e882251a355510a719367ad70227b137343e1bc122015c29391e8545b5272d13a7c2879da3d807",
        ),
        (
            &[0; 144], "0b9845dd429566cdab772ba195d271effe2d0211f16991d766ba749447c5cde569780b2daa66c4b224a2ec2e5d09174c"
        ),
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Blake384::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake384::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Blake384::compare_uppercase(i, e);
        }
    }
}
