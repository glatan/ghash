use super::Blake;
use utils::Hash;

pub struct Blake224(Blake<u32>);

impl Blake224 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new([
            0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
            0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4
        ], salt, 14))
    }
}

impl Default for Blake224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new([
            0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
            0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4
        ], [0; 4], 14))
    }
}

impl Hash for Blake224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x00);
        self.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
