use super::Blake;
use utils::Hash;

pub struct Blake384(Blake<u64>);

impl Blake384 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new([
            0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
            0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
        ], salt))
    }
}

impl Default for Blake384 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new([
            0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
            0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
        ], [0; 4]))
    }
}

impl Hash for Blake384 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x00);
        self.0.compress(16);
        self.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
