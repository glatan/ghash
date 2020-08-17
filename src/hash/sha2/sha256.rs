use super::{Hash, Sha2};

#[rustfmt::skip]
pub const H256: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];

pub struct Sha256(Sha2<u32>);

impl Sha256 {
    pub fn new(message: &[u8]) -> Self {
        Self(Sha2::<u32> {
            message: message.to_vec(),
            word_block: Vec::new(),
            status: H256,
        })
    }
}

impl Hash for Sha256 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut sha256 = Self::new(message);
        sha256.0.padding();
        sha256.0.compress();
        sha256
            .0
            .status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;
    use crate::hash::Test;
    impl Test for Sha256 {}
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
    const TEST_CASES: [(&[u8], &str); 15] = [
        // SHA-256 ("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        (
            "abc".as_bytes(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        // SHA-256 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        // 1 byte 0xbd
        (
            &[0xbd],
            "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b",
        ),
        // 4 bytes 0xc98c8e55
        (
            &[0xc9, 0x8c, 0x8e, 0x55],
            "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504",
        ),
        // 55 bytes of zeros
        (
            &[0; 55],
            "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7",
        ),
        // 56 bytes of zeros
        (
            &[0; 56],
            "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb",
        ),
        // 57 bytes of zeros
        (
            &[0; 57],
            "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785",
        ),
        // 64 bytes of zeros
        (
            &[0; 64],
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        ),
        // 1000 bytes of zeros
        (
            &[0; 1000],
            "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53",
        ),
        // 1000 bytes of 0x41 ‘A
        (
            &[0x41; 1000],
            "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4",
        ),
        // 1005 bytes of 0x55 ‘U’
        (
            &[0x55; 1005],
            "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0",
        ),
        // 1000000 bytes of zeros
        (
            &[0; 1000000],
            "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025",
        ),
        // padding_length > 0
        (
            &[0x30; 54],
            "5e348a8a500ecf192338852a7252ec59b575f5688d8d18e93ba5bb581a980d32",
        ),
        // padding_length == 0
        (
            &[0x30; 55],
            "9f8ef876f51f5313c91cc3f6b8119af09d8bbdd72098fa149b2780eb3591d6be",
        ),
        // padding_length < 0
        (
            &[0x30; 56],
            "bd03ac1428f0ea86f4b83a731ffc7967bb82866d8545322f888d2f6e857ffc18",
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z‘
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Sha256::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Sha256::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Sha256::compare_upperhex(m, e);
        }
    }
}
