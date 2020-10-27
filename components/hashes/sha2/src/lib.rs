mod consts;

pub use utils::Hash;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(not(feature = "minimal"))]
pub use default::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

#[cfg(test)]
mod tests {
    use super::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
    use dev_utils::impl_test;

    const OFFICIAL_224: [(&[u8], &str); 9] = [
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
    const OFFICIAL_256: [(&[u8], &str); 12] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
        (
            "abc".as_bytes(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            &[0xbd],
            "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b",
        ),
        (
            &[0xc9, 0x8c, 0x8e, 0x55],
            "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504",
        ),
        (
            &[0; 55],
            "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7",
        ),
        (
            &[0; 56],
            "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb",
        ),
        (
            &[0; 57],
            "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785",
        ),
        (
            &[0; 64],
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        ),
        (
            &[0; 1000],
            "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53",
        ),
        (
            &[0x41; 1000],
            "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4",
        ),
        (
            &[0x55; 1005],
            "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0",
        ),
        (
            &[0; 1000000],
            "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025",
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z‘
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    const OFFICIAL_384: [(&[u8], &str); 11] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
        (
            "abc".as_bytes(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        ),
        (
            &[],
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            &[0; 111],
            "435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76",
        ),
        (
            &[0; 112],
            "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20",
        ),
        (
            &[0; 113],
            "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21",
        ),
        (
            &[0; 122],
            "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5",
        ),
        (
            &[0; 1000],
            "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca",
        ),
        (
            &[0x41; 1000],
            "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
        ),
        (
            &[0x55; 1005],
            "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec",
        ),
        (
            &[0; 1000000],
            "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81",
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z’
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    const OFFICIAL_512: [(&[u8], &str); 11] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
        (
            "abc".as_bytes(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
        (
            &[],
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            &[0; 111],
            "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c",
        ),
        (
            &[0; 112],
            "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952",
        ),
        (
            &[0; 113],
            "0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544",
        ),
        (
            &[0; 122],
            "4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f",
        ),
        (
            &[0; 1000],
            "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76",
        ),
        (
            &[0x41; 1000],
            "329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af",
        ),
        (
            &[0x55; 1005],
            "59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161",
        ),
        (
            &[0; 1000000],
            "ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed"
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z’
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    const OFFICIAL_512TRUNC224: [(&[u8], &str); 2] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
        (
            "abc".as_bytes(),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
        ),
    ];
    const OFFICIAL_512TRUNC256: [(&[u8], &str); 2] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
        (
            "abc".as_bytes(),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
        ),
    ];
    impl_test!(Sha224, official_224, OFFICIAL_224, Sha224::default());
    impl_test!(Sha256, official_256, OFFICIAL_256, Sha256::default());
    impl_test!(Sha384, official_384, OFFICIAL_384, Sha384::default());
    impl_test!(Sha512, official_512, OFFICIAL_512, Sha512::default());
    impl_test!(
        Sha512Trunc224,
        official_512trunc224,
        OFFICIAL_512TRUNC224,
        Sha512Trunc224::default()
    );
    impl_test!(
        Sha512Trunc256,
        official_512trunc256,
        OFFICIAL_512TRUNC256,
        Sha512Trunc256::default()
    );
}
