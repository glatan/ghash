use super::{Hash, Sha2};
use crate::impl_md_flow;
use std::cmp::Ordering;

pub struct Sha224(Sha2<u32>);

impl Sha224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u32>::new([
            0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0x0F70_E5939,
            0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0x0BEF_A4FA4
        ]))
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
    use crate::impl_test;

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
    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
        (&[0; 1], "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073"),
        (&[0; 2], "ce415cdb385b7a540779f1ed33ae41bac19ac1e55370ac9bc454586d"),
        (&[0; 3], "8e25d811cf8fb0998f130c33062a4162edcf418a621ab04145489337"),
        (&[0; 4], "ac2d118dd210c8401caff1e8b29fa85d29286831505da1b86a91ed63"),
        (&[0; 5], "0e61c65e55810439f418c959dd030c194b2fdaa2ae46b13b3732ff17"),
        (&[0; 6], "817f8f8246eff2259874ddfd534c3d28a4c3f01ed8a0ff6fafe64a4c"),
        (&[0; 7], "fbf6df85218ac5632461a8a17c6f294e6f35264cbfc0a9774a4f665b"),
        (&[0; 8], "02d34274782646a9710f0c8adfac534c45b68379cce3b773533e1f5d"),
        (&[0; 9], "0f55385ac4b55929809a355ba0bac5c5d6194f99ef10f31be1fe3c7e"),
        (&[0; 10], "c9e4f541fded7144f10ed9f2fe63fd493583bf75a6df0fd992b39a77"),
        (&[0; 11], "dafb631661b54386d177236df2c622f4e7e328f738faacc4251073b5"),
        (&[0; 12], "e5436009e365c6f145a40aa6695f8f16477af2699fdf37a78adcd6bf"),
        (&[0; 13], "031bdf6fbe9f434a1784d8845522d05837d9fe0af28eaa82ea01eca0"),
        (&[0; 14], "e8b169887d746bdf6b56f7dfbf665d4c711879fbe17958942807dab7"),
        (&[0; 15], "d97e5683ed780a9f134ef27b5a6617a361bf639a692ae61f78aa8a72"),
        (&[0; 16], "f185bd399e1b659642862ce059e202a19aa873a10294cf30ca5f90eb"),
        (&[0; 17], "e9aeab9919ebafee459cf66b0258ff0241050fb636b409bd63e66367"),
        (&[0; 18], "90853a49c2db40c85196ecbce02e9b08d04537b26a2f7a0991aa5917"),
        (&[0; 19], "4117dc4223752f978bdc8ddaee420fde508bf56e74c36b9741bb1083"),
        (&[0; 20], "bd4f57a4cfb1649cca33372f5c5ad32b993ff73aaf4fb75d52798480"),
        (&[0; 21], "0ba65fa59c3f8e6ae66c2d332f66003f9c9245f0107cc196d95ed166"),
        (&[0; 22], "1429bb40e61d5c2de746da6f3f7ed940729166fd6fa2a8901f4f1602"),
        (&[0; 23], "186defa321457cfda36945c3249b00583798a869564c4961762492d5"),
        (&[0; 24], "4313fb1191ba3abad3756c2b1258c4e062266c6559e0593d795a727c"),
        (&[0; 25], "b18dcbc7511f87aba9e962994bbd651341c41d0a7fbc08d09074d7f0"),
        (&[0; 26], "618e78e569a369aec80f59245a40c316d76b9644dd2d53bce242fc26"),
        (&[0; 27], "cc9db5502f6f3add703ec8b8af9587d8bc42d2f243b7fb1a6f2de74b"),
        (&[0; 28], "453d5a51b142acb31cfbfd8784ed403c9df4034a7a65190cd813094c"),
        (&[0; 29], "7fad75b96f922faff78590e1060871f9d0fde0ac5e267b50ff85fcbb"),
        (&[0; 30], "7803e11a20a80ba994375da677cabb74445dc71c52e650cc0c4be8aa"),
        (&[0; 31], "86af3bad07f40d9c73f20bf6593303de5fea928de0070009e5d3c9ad"),
        (&[0; 32], "b338c76bcffa1a0b3ead8de58dfbff47b63ab1150e10d8f17f2bafdf"),
        (&[0; 33], "d4eb235ef0a1993c5bf563dcbcd9342a14d55a82c26fbfbb095c11c9"),
        (&[0; 34], "5f34970f1e8ddfd8e67f487c852c09c1327f562fe28f5e64897f1988"),
        (&[0; 35], "0d631e2fa8d6833c8c10068665661c7cdb0185c02f68dade5f6f7383"),
        (&[0; 36], "db0859c17e342753a26537025d476b3b59f388da404ff45a47c4a36a"),
        (&[0; 37], "a86f01e2f12e9d07f7f38847127b0e67f8f82d41527b5ee125ecd4a2"),
        (&[0; 38], "cd5ba75fa7983c51204178f8007e06e5cd57c499eef0d71cd87f06e2"),
        (&[0; 39], "9825228ab8be9d8415bb4168f2c5d61af2c61883436b436fad0bb526"),
        (&[0; 40], "a72ba19f5bbf1b5a607b98f7c05d546a6d9a69e3af324768b059753a"),
        (&[0; 41], "261a63079e0e587ac28d8c8866661a83a01a72662d90917f08e5e392"),
        (&[0; 42], "903f459805ba7559df74ee9a816501befbc5337596f03bafe799bd13"),
        (&[0; 43], "656699dce1cffea3ee5d6314b20740d229f896f7fa3c6c0a4cc8cdcf"),
        (&[0; 44], "2183b55cb778e06edb3dded03afe1710057e0c3abe6e0253398222a7"),
        (&[0; 45], "3e2a7683aefb0ebb24911eff62a660b5eec6c9fc0af17e05cbde886d"),
        (&[0; 46], "fb403126d97019c4b7825d9dfca5c9e206c3fdd24c0900cf2e327311"),
        (&[0; 47], "2888aa5590eeb4f54207ed297d883c5dbcc34477098fb5f2947ca0db"),
        (&[0; 48], "f73404bafa0abc9cd5221e99b0d3cc25b47010b75c4e929fdc2ed275"),
        (&[0; 49], "2e71dbe80f6479bb6aae1534db905f181752298ed326401e8eccc45a"),
        (&[0; 50], "4e161fb94a1704ad5b94429e5d1c3ae03429ba4376749e485f947e5d"),
        (&[0; 51], "1291ccfb6c5206b668265fc466a04083653d0dc5c71bbdfca0320d59"),
        (&[0; 52], "a06e646547ee68e1021edc98099e64eaeb90e63feafe436b6c471095"),
        (&[0; 53], "d2c6805d9723b88725b4db73066ff0c28381d394178ac5a85bbf30ea"),
        (&[0; 54], "7d0bd84cf21fb68a3bfe5f07d976d4b0de917c40aac5d3bf215dae8d"),
        (&[0; 55], "7142c3964c75895cc3d1bbdfc851e167a7fdbf2e0c0f2e7212bfd9f5"),
        (&[0; 56], "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804"),
        (&[0; 57], "e5be0b6560c7c801f39c48fd722a5ae927026ab5acd7def5c417c492"),
        (&[0; 58], "27fd7e8dea3ac44d4e54d37dc76ba85608bbf8eb90ff2dec2a1b6000"),
        (&[0; 59], "9ed20c52e5a36f8b3d10eae022115f96138bb70ef75cc06946f3aac0"),
        (&[0; 60], "3fe5b353056d4b16fce534d8de0651b38283d7ffc5b974d8b16346fe"),
        (&[0; 61], "601973dfb0a24ec45efcfccbebaa5b75f0d0fb79f34bb32dae452f69"),
        (&[0; 62], "00adbd146645580c5900d2dc6940992bd86fa1bff73f53f303f45472"),
        (&[0; 63], "ffe75387e7b508381af30782a87bb9150acf03ad960d667e3da870f2"),
        (&[0; 64], "750d81a39c18d3ce27ff3e5ece30b0088f12d8fd0450fe435326294b"),
        (&[0; 65], "3d807488f76e8e468694d647e7022153446afc5ae179828c1e13ba4d"),
        (&[0; 66], "1a38d3fd78b57decf4579b54100570e9b498ecd9c9713b143f1af24b"),
        (&[0; 67], "7124be6c39d1dedab383358551f48d6c90ec9c36a2fa2a03cadc4977"),
        (&[0; 68], "693de19756d917986e114eb3316273ceedc53bf2fb51538c14a4ed48"),
        (&[0; 69], "ac2139d57673a3815c16c82ffb3ca445b722a37a3b17537ceac9275e"),
        (&[0; 70], "85772015dc02c6fe088a2b731e0603b29d9060f6c59ab16ccf07b2f1"),
        (&[0; 71], "3c76898e8f63d13ce03c37bfba507ac51f4f56422c5f4a049ed3a02c"),
        (&[0; 72], "1c637613d3a3ba966e156336414ad6e435558624672b3164e674045a"),
        (&[0; 73], "dbaaf74a268629e01f54986818d647768c2e121eabdd0ddd0e10efc1"),
        (&[0; 74], "fc6abbc293d80daf7f4c39491f754e53ff2bd2ab2fb581424ca824df"),
        (&[0; 75], "357a33210656c94aa82f61e4472e3593faaf0745ea0cc77ccdd1ccb7"),
        (&[0; 76], "a569f911d2cb69bdb1ee161bf1ee5079f3d79cb58c54f3ac180ab318"),
        (&[0; 77], "efa5dd7109303c48ce9e5b4122638bf9c43d7f4a5bccac68e0918081"),
        (&[0; 78], "04623c418a395602c42800c8e6f979e1d57016af3d812db209e3f2d7"),
        (&[0; 79], "23f71f85a115352b02d5ef9c044ac0a28d2cd81471a7f2afbb9b80f3"),
        (&[0; 80], "2d963a001cddd60723faf74919d369d721586e3042ea4c8c02d609d2"),
        (&[0; 81], "2e834c35a2e64c823bb0858b8056352fc19f0d5bee0ee02b48c74971"),
        (&[0; 82], "59f671c2428ebe88e24f77dd72317694823dbc2a9df9a42bda7ff710"),
        (&[0; 83], "beaba9eaddb7351fd08554d530bbf8b74fbaa0fd6325bcf066760374"),
        (&[0; 84], "5d83aa3d546e6875a177f1d8173de095608fd2792f90adf568f37fdc"),
        (&[0; 85], "4095645b24f99198e05e6fefcb5992a26f19c1f1486a1f12aceaeced"),
        (&[0; 86], "6b90c140c9a3adc2202123e3621b69e0d3bd2ec92258c283663b9127"),
        (&[0; 87], "11974912353bd869d10eeba2902f9ca4c9987de43a199ff08f749ed1"),
        (&[0; 88], "c5a4d6236eca7c133acaea436b3e321ce627d70ea9ed115cc53ac82e"),
        (&[0; 89], "630a63279c42a1b17ff77a721c82867ad253025f21753aaf89cc68e1"),
        (&[0; 90], "1a284da296b39f21ac54851a80eb6197812d1270eb63c7f266fd6ef2"),
        (&[0; 91], "ecb84862bb9af631fe200a51a947fd5e16c89fc42abbd5c37bc8164e"),
        (&[0; 92], "a6264881659851331d5ccf11026db993dfd5e7a49628af44411b0c4b"),
        (&[0; 93], "2eecb636058c573b520f59f2f4bccb2f912fdc21017788c36c1d736e"),
        (&[0; 94], "6a7e839c1a85b33ad6a8a10a1034a965be1e580a6b0f1e9a4fe0de7d"),
        (&[0; 95], "a426ea0ccae702cd51c5516b258fa1799059f4ae36aab44f2ffcbb73"),
        (&[0; 96], "e526df281d9828c515d186d74f604ac7928992deaf276c6b62caeac5"),
        (&[0; 97], "18d4fbe212c1e1c51511766a0cd0f823457dd320b19dfa3e1af895a7"),
        (&[0; 98], "8cf89bdc21b08ae0dfd8836613e45f696c65683ba525d74348c6a93b"),
        (&[0; 99], "773c17542971725d5f7f9529a4de927a9c9ea43f944a93eaf6244b20"),
        (&[0; 100], "a93db08e3b421bbe48b82afba286c64b9c6c903ce599f245fc32901c"),
        (&[0; 101], "041d5619e8baacc9ab5da29cadf8d95fa31c50aafb665bcf0fec39ce"),
        (&[0; 102], "9c8caa13a893eb2d2a01a676c4f76d84f8823fb0cfc62a9bfe106d36"),
        (&[0; 103], "739ffa2cc87c0faba8dfbea159436968c8fd146a36205e9e3eafcc1e"),
        (&[0; 104], "cfc14712738f00d36bfcb6814c73f879652ea2e5e0534e3db52b53d3"),
        (&[0; 105], "fe2dda7223da390c0739022163c04f787c3afd7910b6a7d5d522729a"),
        (&[0; 106], "db043e7e5d9af5d7928653259d489e3ef4933a6ec2f4a319d30848c6"),
        (&[0; 107], "8a9762c357d5b7c55ee9c145fde3f1d113f872ab0d215ead9488c0b0"),
        (&[0; 108], "686fd6bde3579240e8e3c71446e75db20a6be1e093ad7181469cef76"),
        (&[0; 109], "6051faeceddde094e6d7f6811d305f463c94ad6f9d94e8b9469aa2b3"),
        (&[0; 110], "b6325415d0756be682388099f7d3bd94ada608938f880e00ff167e15"),
        (&[0; 111], "d78aeba56a04e0f7b1e40775aa6cc9b5072e3b85c0d17fdb786b599a"),
        (&[0; 112], "bc038a9b27efebcbc349a92da769d259460ab645a4598b6169aea7e4"),
        (&[0; 113], "4ed2c17b83d1624d9fdc3a86f99f8f88d2c881f7ed1a75f05483038f"),
        (&[0; 114], "0822320dcb9593e0d9970ba1e9f118fe224e6ff5f29cc9322c7f51ad"),
        (&[0; 115], "aac85e7d6059cfdc2cc1acd51b63b4f045887eabe356b2866ea3df8f"),
        (&[0; 116], "d4af3fea646a50e98677c12dc5090b6da470ff0ef628a5197feb0247"),
        (&[0; 117], "002f1bcdde068a845ff5f92af5d788dade0638d61dddf472e3f1110e"),
        (&[0; 118], "04078e71e30daa7ca2d3fd15ffd6db1b56256ed1d909e91b6b83d0eb"),
        (&[0; 119], "32f3ffa6a58237265c4a0f248960169666e2099dc7d9981308b2157d"),
        (&[0; 120], "83438028e7817c90b386a11c9a4e051f821b37c818bb4b5c08279584"),
        (&[0; 121], "d517ff41f8dbba3ba126a2c699a2fb3bb854d3ce3068332720b1158c"),
        (&[0; 122], "3de11057f737cfdf915e4196a728ee5c18561dc28a228d8deabb87f8"),
        (&[0; 123], "6650f85110dedebf06929caf8b52f0d05bf2afd15c8462fe33ff88c9"),
        (&[0; 124], "5bb3f289ecd647d536afed20181036206c77b0a4bad8a21a9a462684"),
        (&[0; 125], "3ff950ae938f10a7eb015031d87b5803f42aaa84f2e1d25bf9619791"),
        (&[0; 126], "cdb6050680f5c98b2589e5c30329816f74b4c9c0863a75779acbe5bd"),
        (&[0; 127], "dd731fb541b71c03c4af752fd71203e78f3d77a8530b5f3ef54c516c"),
    ];
    impl_test!(Sha224, official, OFFICIAL, Sha224::default());
    impl_test!(Sha224, zero_fill, ZERO_FILL, Sha224::default());
}
