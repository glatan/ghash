use super::{Hash, Input, Sha2};

#[rustfmt::skip]
pub const H384: [u64; 8] = [
    0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
    0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4,
];

pub struct Sha384(Sha2<u64>);

impl Sha384 {
    pub const fn new() -> Self {
        Self(Sha2::<u64> {
            message: Vec::new(),
            word_block: Vec::new(),
            status: H384,
        })
    }
}

impl Input for Sha384 {
    fn input(&mut self, message: &[u8]) {
        self.0.input(message)
    }
}

impl Hash for Sha384 {
    fn hash(message: &[u8]) -> Vec<u8> {
        let mut sha384 = Self::new();
        sha384.0.input(message);
        sha384.0.padding();
        sha384.0.round();
        sha384.0.status[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha384;
    use crate::hash::Test;
    impl Test<Sha384> for Sha384 {}
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
    const TEST_CASES: [(&[u8], &str); 14] = [
        // SHA-384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
        (
            "abc".as_bytes(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        // SHA-384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        ),
        // 0 byte (null message)
        (
            &[],
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        // 111 bytes of zeros
        (
            &[0; 111],
            "435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76",
        ),
        // 112 bytes of zeros
        (
            &[0; 112],
            "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20",
        ),
        // 113 bytes of zeros
        (
            &[0; 113],
            "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21",
        ),
        // 122 bytes of zeros
        (
            &[0; 122],
            "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5",
        ),
        // 1000 bytes of zeros
        (
            &[0; 1000],
            "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca",
        ),
        // 1000 bytes of 0x41 ‘A’
        (
            &[0x41; 1000],
            "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
        ),
        // 1005 bytes of 0x55 ‘U’
        (
            &[0x55; 1005],
            "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec",
        ),
        // 1000000 bytes of zeros
        (
            &[0; 1000000],
            "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81",
        ),
        // padding_length > 0
        (
            &[0x30; 110],
            "30d25fd948cf25eaeba20ef6315593212271e9d1dae6c3770f590c8fadb46e7b29fda2dae7cd27ccdd3b48ad18c8b728",
        ),
        // padding_length == 0
        (
            &[0x30; 111],
            "8e3d07afccdca92c400d024c468f61bc1c9283ed3c1132f6d3543495bbf8afa1fc2cd0f230f1669f5b635fccd103b6b8",
        ),
        // padding_length < 0
        (
            &[0x30; 112],
            "efbaad694008892f0b040bfe453c573d5e0ca44835eb860e20b17a0ead6df3a58ed61723dcb62d2db564e23bce166f95",
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z’
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    #[test]
    fn bytes() {
        for (i, e) in TEST_CASES.iter() {
            Sha384::compare_bytes(i, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha384::compare_lowercase(i, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (i, e) in TEST_CASES.iter() {
            Sha384::compare_uppercase(i, e);
        }
    }
}
