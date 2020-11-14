use alloc::vec::Vec;
use core::cmp::Ordering;

use super::{impl_md_flow, Sha2, H224};
use utils::Hash;

pub struct Sha224(Sha2<u32>);

impl Sha224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u32>::new(H224))
    }
}

impl Hash for Sha224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha224;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
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

    impl_test!(Sha224, official, OFFICIAL, Sha224::default());
}
