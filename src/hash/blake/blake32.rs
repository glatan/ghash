use super::{Blake, Hash};

#[rustfmt::skip]
const IV32: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];

pub struct Blake32(Blake<u32>);

impl Blake32 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, IV32, 256))
    }
}

impl Hash for Blake32 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake32 = Self::new(message);
        blake32.0.padding();
        blake32.0.compress(10);
        blake32
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake32;
    use crate::hash::Test;
    impl Test for Blake32 {}
    const TEST_CASES: [(&[u8], &str); 5] = [
        // https://ehash.iaik.tugraz.at/uploads/0/06/Blake.pdf
        (
            &[0; 1],
            "d1e39b457d2250b4f5b152e74157fba4c1b423b87549106b07fd3a3e7f4aeb28",
        ),
        (
            &[0; 72],
            "8a638488c318c5a8222a1813174c36b4bb66e45b09afddfd7f2b2fe3161b7a6d",
        ),
        (
            &[0; 54],
            "e48be2d65ce7e11d46154b9559f819e41b4219b550e682d06fcffebfdf7c8859",
        ),
        (
            &[0; 55],
            "a23e90be90c71273fb1ffb4b04eca3da0d78f63b6562c9b38e27230469e2eb2d",
        ),
        (
            &[0; 56],
            "3afca2602886add57dd78991e2a86806b76627abb6c8c46cdbaeff937ae10adf",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_upperhex(m, e);
        }
    }
}
