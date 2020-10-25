use super::Blake;
use utils::Hash;

pub struct Blake32(Blake<u32>);

impl Blake32 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new([
            0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
            0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
        ], salt, 10))
    }
}

impl Default for Blake32 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new([
            0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
            0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
        ], [0; 4], 10))
    }
}

impl Hash for Blake32 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.blake(message, 0x01);
        self.0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
