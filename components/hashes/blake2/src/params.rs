use core::fmt;

struct Params<const SP_LEN: usize> {
    digest_byte_len: u8,
    key_byte_len: u8,
    fanout: u8,
    maximum_depth: u8,
    leaf_maximum_len: u32,
    node_offset: u64,
    node_depth: u8,
    inner_hash_byte_len: u8,
    salt: [u8; SP_LEN],
    personalization: [u8; SP_LEN],
}

impl<const SP_LEN: usize> fmt::Debug for Params<SP_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Params")
            .field("digest_byte_len", &self.digest_byte_len)
            .field("key_byte_len", &self.key_byte_len)
            .field("salt", &self.salt)
            .field("personalization", &self.personalization)
            .field("fanout", &self.fanout)
            .field("maximum_depth", &self.maximum_depth)
            .field("leaf_maximum_len", &self.leaf_maximum_len)
            .field("node_offset", &self.node_offset)
            .field("node_depth", &self.node_depth)
            .field("inner_hash_byte_len", &self.inner_hash_byte_len)
            .finish()
    }
}

macro_rules! impl_blake_params {
    (pub struct $T:ident(Params<$SP_LEN:expr,>)) => {
        #[derive(Debug)]
        pub struct $T(Params<$SP_LEN>);

        impl $T {
            pub const fn with_digest_len(digest_byte_len: u8) -> Self {
                Self(Params {
                    digest_byte_len,
                    key_byte_len: 0,
                    fanout: 1,
                    maximum_depth: 1,
                    leaf_maximum_len: 0,
                    node_offset: 0,
                    node_depth: 0,
                    inner_hash_byte_len: 0,
                    salt: [0; $SP_LEN],
                    personalization: [0; $SP_LEN],
                })
            }

            pub fn digest_byte_len(&mut self, digest_byte_len: u8) -> &mut Self {
                self.0.digest_byte_len = digest_byte_len;
                self
            }

            pub fn key_byte_len(&mut self, key_byte_len: u8) -> &mut Self {
                self.0.key_byte_len = key_byte_len;
                self
            }

            pub fn salt(&mut self, salt: [u8; $SP_LEN]) -> &mut Self {
                self.0.salt = salt;
                self
            }

            pub fn personalization(&mut self, personalization: [u8; $SP_LEN]) -> &mut Self {
                self.0.personalization = personalization;
                self
            }

            pub fn fanout(&mut self, fanout: u8) -> &mut Self {
                self.0.fanout = fanout;
                self
            }

            pub fn maximum_depth(&mut self, maximum_depth: u8) -> &mut Self {
                self.0.maximum_depth = maximum_depth;
                self
            }

            pub fn leaf_maximum_len(&mut self, leaf_maximum_len: u32) -> &mut Self {
                self.0.leaf_maximum_len = leaf_maximum_len;
                self
            }

            pub fn node_offset(&mut self, node_offset: u64) -> &mut Self {
                self.0.node_offset = node_offset;
                self
            }

            pub fn node_depth(&mut self, node_depth: u8) -> &mut Self {
                self.0.node_depth = node_depth;
                self
            }

            pub fn inner_hash_byte_len(&mut self, inner_hash_byte_len: u8) -> &mut Self {
                self.0.inner_hash_byte_len = inner_hash_byte_len;
                self
            }
        }
    };
}

impl_blake_params!(pub struct Blake2sParams(Params<8,>));
impl_blake_params!(pub struct Blake2bParams(Params<16,>));

impl Blake2sParams {
    pub const fn to_words(&self) -> [u32; 8] {
        let node_offset = self.0.node_offset.to_le();
        let salt = u64::from_le_bytes(self.0.salt);
        let personalization = u64::from_le_bytes(self.0.personalization);

        [
            // 0 ~ 3
            u32::from_le_bytes([
                self.0.digest_byte_len,
                self.0.key_byte_len,
                self.0.fanout,
                self.0.maximum_depth,
            ]),
            // 4 ~ 7
            self.0.leaf_maximum_len.to_le(),
            // 8 ~ 11
            (node_offset >> 32) as u32,
            // 12 ~ 15
            (node_offset as u32) & 0xFFFF_0000
                | ((self.0.node_depth as u32) << 8) & 0x0000_FF00
                | (self.0.inner_hash_byte_len as u32) & 0x0000_00FF,
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
    pub const fn to_words(&self) -> [u64; 8] {
        let leaf_maximum_len = self.0.leaf_maximum_len.to_le_bytes();
        let salt = u128::from_le_bytes(self.0.salt);
        let personalization = u128::from_le_bytes(self.0.personalization);

        [
            // 0 ~ 7
            u64::from_le_bytes([
                self.0.digest_byte_len,
                self.0.key_byte_len,
                self.0.fanout,
                self.0.maximum_depth,
                leaf_maximum_len[0],
                leaf_maximum_len[1],
                leaf_maximum_len[2],
                leaf_maximum_len[3],
            ]),
            // 8 ~ 15
            self.0.node_offset.to_le(),
            // 16 ~ 23
            u64::from_le_bytes([
                self.0.node_depth,
                self.0.inner_hash_byte_len,
                0,
                0,
                0,
                0,
                0,
                0,
            ]),
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

struct XOFParams<XOFLen: Sized + fmt::Debug, const SP_LEN: usize> {
    digest_byte_len: u8,
    key_byte_len: u8,
    fanout: u8,
    maximum_depth: u8,
    leaf_maximum_len: u32,
    node_offset: u32,
    xof_digest_length: XOFLen,
    node_depth: u8,
    inner_hash_byte_len: u8,
    salt: [u8; SP_LEN],
    personalization: [u8; SP_LEN],
}

impl<XOFLen: Sized + fmt::Debug, const SP_LEN: usize> fmt::Debug for XOFParams<XOFLen, SP_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Params")
            .field("digest_byte_len", &self.digest_byte_len)
            .field("key_byte_len", &self.key_byte_len)
            .field("fanout", &self.fanout)
            .field("maximum_depth", &self.maximum_depth)
            .field("leaf_maximum_len", &self.leaf_maximum_len)
            .field("node_offset", &self.node_offset)
            .field("xof_digest_length", &self.xof_digest_length)
            .field("node_depth", &self.node_depth)
            .field("inner_hash_byte_len", &self.inner_hash_byte_len)
            .field("salt", &self.salt)
            .field("personalization", &self.personalization)
            .finish()
    }
}

macro_rules! impl_blake_xof_params {
    (pub struct $T:ident(XOFParams<$XOF_LEN:ty, $SP_LEN:expr,>);
        ByteLength = $ByteLength:expr;
    ) => {
        #[derive(Debug)]
        pub struct $T(XOFParams<$XOF_LEN, $SP_LEN>);

        impl $T {
            pub const fn with_xof_digest_length(xof_digest_length: $XOF_LEN) -> Self {
                Self(XOFParams {
                    digest_byte_len: $ByteLength,
                    key_byte_len: 0,
                    fanout: 0,
                    maximum_depth: 0,
                    leaf_maximum_len: $ByteLength,
                    node_offset: 0,
                    xof_digest_length,
                    node_depth: 0,
                    inner_hash_byte_len: $ByteLength,
                    salt: [0; $SP_LEN],
                    personalization: [0; $SP_LEN],
                })
            }

            pub fn digest_byte_len(&mut self, digest_byte_len: u8) -> &mut Self {
                self.0.digest_byte_len = digest_byte_len;
                self
            }

            pub fn key_byte_len(&mut self, key_byte_len: u8) -> &mut Self {
                self.0.key_byte_len = key_byte_len;
                self
            }

            pub fn fanout(&mut self, fanout: u8) -> &mut Self {
                self.0.fanout = fanout;
                self
            }

            pub fn maximum_depth(&mut self, maximum_depth: u8) -> &mut Self {
                self.0.maximum_depth = maximum_depth;
                self
            }

            pub fn leaf_maximum_len(&mut self, leaf_maximum_len: u32) -> &mut Self {
                self.0.leaf_maximum_len = leaf_maximum_len;
                self
            }

            pub fn node_offset(&mut self, node_offset: u32) -> &mut Self {
                self.0.node_offset = node_offset;
                self
            }

            pub fn xof_digest_length(&mut self, xof_digest_length: $XOF_LEN) -> &mut Self {
                self.0.xof_digest_length = xof_digest_length;
                self
            }

            pub fn node_depth(&mut self, node_depth: u8) -> &mut Self {
                self.0.node_depth = node_depth;
                self
            }

            pub fn inner_hash_byte_len(&mut self, inner_hash_byte_len: u8) -> &mut Self {
                self.0.inner_hash_byte_len = inner_hash_byte_len;
                self
            }

            pub fn salt(&mut self, salt: [u8; $SP_LEN]) -> &mut Self {
                self.0.salt = salt;
                self
            }

            pub fn personalization(&mut self, personalization: [u8; $SP_LEN]) -> &mut Self {
                self.0.personalization = personalization;
                self
            }
        }
    };
}

impl_blake_xof_params!(
    pub struct Blake2xsParams(XOFParams<u16, 8,>);
    ByteLength = 32;
);
impl_blake_xof_params!(
    pub struct Blake2xbParams(XOFParams<u32, 16,>);
    ByteLength = 64;
);

impl Blake2xsParams {
    pub const fn to_words(&self) -> [u32; 8] {
        let salt = u64::from_le_bytes(self.0.salt);
        let personalization = u64::from_le_bytes(self.0.personalization);

        [
            // 0 ~ 3
            u32::from_le_bytes([
                self.0.digest_byte_len,
                self.0.key_byte_len,
                self.0.fanout,
                self.0.maximum_depth,
            ]),
            // 4 ~ 7
            self.0.leaf_maximum_len.to_le(),
            // 8 ~ 11
            self.0.node_offset.to_le(),
            // 12 ~ 15
            ((self.0.xof_digest_length as u32) << 16) & 0xFFFF_0000
                | ((self.0.node_depth as u32) << 8) & 0x0000_FF00
                | (self.0.inner_hash_byte_len as u32) & 0x0000_00FF,
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

impl Blake2xbParams {
    pub const fn to_words(&self) -> [u64; 8] {
        let leaf_maximum_len = self.0.leaf_maximum_len.to_le_bytes();
        let salt = u128::from_le_bytes(self.0.salt);
        let personalization = u128::from_le_bytes(self.0.personalization);

        [
            // 0 ~ 7
            u64::from_le_bytes([
                self.0.digest_byte_len,
                self.0.key_byte_len,
                self.0.fanout,
                self.0.maximum_depth,
                leaf_maximum_len[0],
                leaf_maximum_len[1],
                leaf_maximum_len[2],
                leaf_maximum_len[3],
            ]),
            // 8 ~ 15
            ((self.0.node_offset.to_le() as u64) << 32) & 0xFFFF_FFFF_0000_0000
                | (self.0.xof_digest_length.to_le() as u64 & 0x0000_0000_FFFF_FFFF),
            // 16 ~ 23
            u64::from_le_bytes([
                self.0.node_depth,
                self.0.inner_hash_byte_len,
                0,
                0,
                0,
                0,
                0,
                0,
            ]),
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
        let params = Blake2sParams::with_digest_len(0x20).to_words();
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
        let params: [u64; 8] = Blake2bParams::with_digest_len(0x40)
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
