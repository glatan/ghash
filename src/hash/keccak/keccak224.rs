// SHA-3 Submission
// https://keccak.team/files/Keccak-submission-3.pdf
// Keccak-224: [r=1152, c=448]

use super::{Hash, Keccak, Message};

pub struct Keccak224(Keccak);

impl Keccak224 {
    pub const fn new() -> Self {
        Self(Keccak::new())
    }
}

impl Message for Keccak224 {
    fn message(&mut self, message: &[u8]) {
        self.0.message(message);
    }
}

impl Hash for Keccak224 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut keccak224 = Self::new();
        keccak224.0.set_params(1152, 448, 224);
        keccak224.0.hash(message)
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak224;
    use crate::hash::Test;
    impl Test for Keccak224 {}
    const TEST_CASES: [(&[u8], &str); 1] = [(
        "".as_bytes(),
        "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
    )];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Keccak224::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Keccak224::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Keccak224::compare_upperhex(m, e);
        }
    }
}
