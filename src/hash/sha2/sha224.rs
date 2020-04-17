use super::{Hash, Sha2_32bit};

#[rustfmt::skip]
pub const H224: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70_E5939,
    0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEF_A4FA4
];

pub struct Sha224(Sha2_32bit);

impl Sha224 {
    pub const fn new() -> Self {
        Self(Sha2_32bit {
            input: Vec::new(),
            word_block: Vec::new(),
            status: H224,
        })
    }
    fn padding(&mut self) {
        self.0.padding();
    }
    fn round(&mut self) {
        self.0.round();
    }
}

impl Hash for Sha224 {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut sha224 = Self::new();
        sha224.0.input = input.to_vec();
        sha224.padding();
        sha224.round();
        sha224.0.status[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::Sha224;
    use crate::hash::Test;
    impl Test<Sha224> for Sha224 {}
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
    const TEST_CASES: [(&[u8], &str); 9] = [
        (
            "abc".as_bytes(),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        // SHA-224 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        ),
        // 1 byte 0xff
        (
            &[0xff],
            "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5",
        ),
        // 4 bytes 0xe5e09924
        (
            &[0xe5, 0xe0, 0x99, 0x24],
            "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d",
        ),
        // 56 bytes of zeros
        (
            &[0; 56],
            "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804",
        ),
        // 1000 bytes of 0x51 ‘Q’
        (
            &[0x51; 1000],
            "3706197f66890a41779dc8791670522e136fafa24874685715bd0a8a",
        ),
        // 1000 bytes of 0x41 ‘A’
        (
            &[0x41; 1000],
            "a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce",
        ),
        // 1005 bytes of 0x99
        (
            &[0x99; 1005],
            "cb00ecd03788bf6c0908401e0eb053ac61f35e7e20a2cfd7bd96d640",
        ),
        // 1000000 bytes of zeros
        (
            &[0; 1000000],
            "3a5d74b68f14f3a4b2be9289b8d370672d0b3d2f53bc303c59032df3",
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x41 ‘A’
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003f (1610612799) bytes of 0x84
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Sha224::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha224::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha224::compare_uppercase(i, e);
        }
    }
}