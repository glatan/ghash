use super::{Blake, Hash};

#[rustfmt::skip]
const IV48: [u64; 8] = [
    0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
    0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
];

pub struct Blake48(Blake<u64>);

impl Blake48 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u64>::new(message, IV48, 384))
    }
}

impl Hash for Blake48 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake48 = Self::new(message);
        blake48.0.padding();
        blake48.0.compress(14);
        blake48.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake48;
    use crate::hash::Test;
    impl Test for Blake48 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://ehash.iaik.tugraz.at/uploads/0/06/Blake.pdf
        (
            &[0; 1],
            "f8a8d703fd654db9319ac478af593def821494cb23aeb57680a5ea1aea0a65cc7b72e69f6893efd23e5233511ea5d425",
        ),
        (
            &[0; 144],
            "c802316791fd7c1395d568c94cc9351e27fba17b5c990c9aa920bf9bd1611921e283a7e600f7b8949cfa4deb2f8a667f",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake48::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake48::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake48::compare_upperhex(m, e);
        }
    }
}
