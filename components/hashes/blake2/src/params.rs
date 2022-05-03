pub struct Params<const SP_LEN: usize> {
    digest_byte_len: u8,
    key_byte_len: u8,
    salt: [u8; SP_LEN],
    personalization: [u8; SP_LEN],
    fanout: u8,
    maximum_depth: u8,
    leaf_maximum_len: u32,
    node_offset: u64,
    node_depth: u8,
    inner_hash_byte_len: u8,
}

impl<const SP_LEN: usize> Default for Params<SP_LEN> {
    fn default() -> Self {
        Self {
            digest_byte_len: 1,
            key_byte_len: 0,
            salt: [0; SP_LEN],
            personalization: [0; SP_LEN],
            fanout: 1,
            maximum_depth: 1,
            leaf_maximum_len: 0,
            node_offset: 0,
            node_depth: 0,
            inner_hash_byte_len: 0,
        }
    }
}

macro_rules! impl_blake_params {
    ($T:ident, $SP_LEN:expr) => {
        pub type $T = Params<$SP_LEN>;

        impl $T {
            pub fn digest_byte_len(&mut self, digest_byte_len: u8) -> &mut Self {
                self.digest_byte_len = digest_byte_len;
                self
            }

            pub fn key_byte_len(&mut self, key_byte_len: u8) -> &mut Self {
                self.key_byte_len = key_byte_len;
                self
            }

            pub fn salt(&mut self, salt: [u8; $SP_LEN]) -> &mut Self {
                self.salt = salt;
                self
            }

            pub fn personalization(&mut self, personalization: [u8; $SP_LEN]) -> &mut Self {
                self.personalization = personalization;
                self
            }

            pub fn fanout(&mut self, fanout: u8) -> &mut Self {
                self.fanout = fanout;
                self
            }

            pub fn maximum_depth(&mut self, maximum_depth: u8) -> &mut Self {
                self.maximum_depth = maximum_depth;
                self
            }

            pub fn leaf_maximum_len(&mut self, leaf_maximum_len: u32) -> &mut Self {
                self.leaf_maximum_len = leaf_maximum_len;
                self
            }

            pub fn node_offset(&mut self, node_offset: u64) -> &mut Self {
                self.node_offset = node_offset;
                self
            }

            pub fn node_depth(&mut self, node_depth: u8) -> &mut Self {
                self.node_depth = node_depth;
                self
            }

            pub fn inner_hash_byte_len(&mut self, inner_hash_byte_len: u8) -> &mut Self {
                self.inner_hash_byte_len = inner_hash_byte_len;
                self
            }
        }
    };
}

impl_blake_params!(Blake2sParams, 8);
impl_blake_params!(Blake2bParams, 16);

impl Blake2sParams {
    pub fn to_words(&self) -> [u32; 8] {
        let node_offset = self.node_offset.to_le();
        let salt = u64::from_le_bytes(self.salt);
        let personalization = u64::from_le_bytes(self.personalization);

        [
            // 0 ~ 3
            u32::from_le_bytes([
                self.digest_byte_len,
                self.key_byte_len,
                self.fanout,
                self.maximum_depth,
            ]),
            // 4 ~ 7
            self.leaf_maximum_len.to_le(),
            // 8 ~ 11
            (node_offset >> 32) as u32,
            // 12 ~ 15
            (node_offset as u32) & 0xFFFF_0000
                | ((self.node_depth as u32) << 8) & 0x0000_FF00
                | (self.inner_hash_byte_len as u32) & 0x0000_00FF,
            // 16 ~ 19
            (salt >> 32) as u32,
            // 20 ~ 23
            salt as u32,
            // 24 ~ 27
            (personalization >> 32) as u32,
            // 28 ~ 31
            personalization as u32,
        ]
    }
}

impl Blake2bParams {
    pub fn to_words(&self) -> [u64; 8] {
        let leaf_maximum_len = self.leaf_maximum_len.to_le_bytes();
        let salt = u128::from_le_bytes(self.salt);
        let personalization = u128::from_le_bytes(self.personalization);

        [
            // 0 ~ 7
            u64::from_le_bytes([
                self.digest_byte_len,
                self.key_byte_len,
                self.fanout,
                self.maximum_depth,
                leaf_maximum_len[0],
                leaf_maximum_len[1],
                leaf_maximum_len[2],
                leaf_maximum_len[3],
            ]),
            // 8 ~ 15
            self.node_offset.to_le(),
            // 16 ~ 23
            u64::from_le_bytes([self.node_depth, self.inner_hash_byte_len, 0, 0, 0, 0, 0, 0]),
            // 24 ~ 31
            0u64,
            // 32 ~ 39
            (salt >> 64) as u64,
            // 40 ~ 47
            salt as u64,
            // 48 ~ 55
            (personalization >> 64) as u64,
            // 56 ~ 63
            personalization as u64,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{Blake2bParams, Blake2sParams};

    #[test]
    fn example_blake2s() {
        let params = Blake2sParams::default().digest_byte_len(0x20).to_words();
        let expected: [u32; 8] = [
            0x0101_0020,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
        ];
        assert_eq!(expected, params);
    }

    #[test]
    fn example_blake2b() {
        let params: [u64; 8] = Blake2bParams::default()
            .digest_byte_len(0x40)
            .key_byte_len(0x20)
            .salt([0x55; 16])
            .personalization([0xEE; 16])
            .to_words();
        let expected: [u64; 8] = [
            0x0000_0000_0101_2040,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x5555_5555_5555_5555,
            0x5555_5555_5555_5555,
            0xEEEE_EEEE_EEEE_EEEE,
            0xEEEE_EEEE_EEEE_EEEE,
        ];
        assert_eq!(expected, params);
    }
}
