use super::{Blake, Hash, Message};

#[rustfmt::skip]
const H64: [u64; 8] = [
    0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
];

pub struct Blake64(Blake<u64>);

impl Blake64 {
    pub const fn new() -> Self {
        Self(Blake::<u64> {
            message: Vec::new(),
            word_block: Vec::new(),
            salt: [0; 4],
            l: 0,
            h: H64,
            t: [0; 2],
            v: [0; 16],
            bit: 512,
        })
    }
}

impl Message for Blake64 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Blake64 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake64 = Self::new();
        blake64.0.message(message);
        blake64.0.set_counter();
        blake64.0.padding();
        blake64.0.compress(14);
        blake64
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake64;
    use crate::hash::Test;
    impl Test for Blake64 {}
    const TEST_CASES: [(&[u8], &str); 2] = [
        // https://ehash.iaik.tugraz.at/uploads/0/06/Blake.pdf
        (
            &[0; 1],
            "765f7084548226c3e6f4779b954661df49a272e2ba16635f17a3093756aa93642a92e5bddb21a3218f72b7fd44e9fa19f86a86334ebeda0f4d4204bf3b6bed68",
        ),
        (
            &[0; 144],
            "eab730280428210571f3f8dee678a9b1bbef58df55471265b71e262b8effba2533c15317c3e9f897b269ed4146aed0f3a29827060055ca14652753efe20a913e",
        ),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake64::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake64::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake64::compare_upperhex(m, e);
        }
    }
}
