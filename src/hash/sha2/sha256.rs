use super::{Hash, Sha2};

pub struct Sha256(Sha2<u32>);

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u32>::new([
            0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
            0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
        ]))
    }
}

impl Hash for Sha256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message);
        self.0.compress();
        self.0
            .status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 12] = [
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
    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); 128] = [
        (&[0; 0], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (&[0; 1], "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        (&[0; 2], "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
        (&[0; 3], "709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"),
        (&[0; 4], "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
        (&[0; 5], "8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4"),
        (&[0; 6], "b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44"),
        (&[0; 7], "837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619"),
        (&[0; 8], "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"),
        (&[0; 9], "3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d"),
        (&[0; 10], "01d448afd928065458cf670b60f5a594d735af0172c8d67f22a81680132681ca"),
        (&[0; 11], "71b6c1d53832f789a7f2435a7c629245fa3761ad8487775ebf4957330213a706"),
        (&[0; 12], "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b"),
        (&[0; 13], "dd46c3eebb1884ff3b5258c0a2fc9398e560a29e0780d4b53869b6254aa46a96"),
        (&[0; 14], "e7ecebbc590bc88b3761fa6cd03d749f87463dabb67021a5c6768c25ec68b3f2"),
        (&[0; 15], "5322fecfc92a5e3248a297a3df3eddfb9bd9049504272e4f572b87fa36d4b3bd"),
        (&[0; 16], "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"),
        (&[0; 17], "0a88111852095cae045340ea1f0b279944b2a756a213d9b50107d7489771e159"),
        (&[0; 18], "60daa3a5f7dbfa200f8c82840ecf5b42640b70f3b7218a4c6bbd67db542e75a4"),
        (&[0; 19], "d6fd62f5ce537d90ea3ea45841b17f34d727bcbc4128748cba14fb87c0ffd9d1"),
        (&[0; 20], "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90"),
        (&[0; 21], "c90232586b801f9558a76f2f963eccd831d9fe6775e4c8f1446b2331aa2132f2"),
        (&[0; 22], "6a4875ddaceaa91fb3369f0f6d962f77442daf1b1d97733457d12bcabdf79441"),
        (&[0; 23], "015275e61fa0d0751c1d9f45541c7804c895404455470710ade3786f282f2da0"),
        (&[0; 24], "9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0"),
        (&[0; 25], "61126de1b795b976f3ac878f48e88fa77a87d7308ba57c7642b9e1068403a496"),
        (&[0; 26], "659d36ca563ba4622daabb36a71dafaf6060cdcbf89bb12e75426198496d272c"),
        (&[0; 27], "ea49aa9f6f6cf2d53d454e628ba5a339cc000230c4651655d0237711d747f50b"),
        (&[0; 28], "3addfb141cd7c9c4c6543a82191a3707ac29c7a041217782e61d4d91c691aee8"),
        (&[0; 29], "11e431c215c5bd334cecbd43148274edf3ffdbd6cd6479fe279577fbe5f52ce6"),
        (&[0; 30], "0679246d6c4216de0daa08e5523fb2674db2b6599c3b72ff946b488a15290b62"),
        (&[0; 31], "fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989"),
        (&[0; 32], "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"),
        (&[0; 33], "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9"),
        (&[0; 34], "eb142b0cae0baa72a767ebc0823d1be94e14c5bfc52d8e417fc4302fceb6240c"),
        (&[0; 35], "0d5535e13cc9708d0ff0289af2fae27e564b6bcbcd9242f5140d96957744a517"),
        (&[0; 36], "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e"),
        (&[0; 37], "ab24a95f44ceca5d2aed4b6d056adddd8539f44c6cd6ca506534e830c82ea8a8"),
        (&[0; 38], "762b023699a0e48aa95763f0cf7c0467f1d6e9880308c78ebbc1c423de7072d3"),
        (&[0; 39], "94c11ed3c3c73016adb92416352678e169cbe47bb48bc27e5e9d466115b06252"),
        (&[0; 40], "2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb"),
        (&[0; 41], "9e1736c43d19118e6ce4302118af337109491ecc52757dfb949bad6a7940b0c2"),
        (&[0; 42], "094c4931fdb2f2af417c9e0322a9716006e8211fe9017f671ac6e3251300acca"),
        (&[0; 43], "859732b97382a08583d6a67f5842486505e50bee754bd9b57ac3abf81b9714f2"),
        (&[0; 44], "85759b3811ff7dc47b03792ac85317be51431a3f9e01dcafce317ed736a391b0"),
        (&[0; 45], "8a1020634191c27b63d3c2aa45b723f696ddf2743ca8996a33ed0e47ddd7fc07"),
        (&[0; 46], "878f32f76b159494f5a39f9321616c6068cdb82e88df89bcc739bbc1ea78e1f9"),
        (&[0; 47], "140eda45fe001c0fe47edd7fc509ff1882d46fbcb7c7437d893c1fb83012e433"),
        (&[0; 48], "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1"),
        (&[0; 49], "78877fa898f0b4c45c9c33ae941e40617ad7c8657a307db62bc5691f92f4f60e"),
        (&[0; 50], "cc2786e1f9910a9d811400edcddaf7075195f7a16b216dcbefba3bc7c4f2ae51"),
        (&[0; 51], "8e8fe47e4a33b178bf0433d8050cb0ad7ec323fbdeeab3ecfd857b4ce1805b7a"),
        (&[0; 52], "7955cb2de90dd9efc6df9fdbf5f5d10c114f4135a9a6b52db1003be749e32f7a"),
        (&[0; 53], "353fd628b7f6e7d426e5d6a27d1bc3ac22fa7f812e7594cf2ec5ca1175785b50"),
        (&[0; 54], "ea659cdc838619b3767c057fdf8e6d99fde2680c5d8517eb06761c0878d40c40"),
        (&[0; 55], "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"),
        (&[0; 56], "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"),
        (&[0; 57], "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"),
        (&[0; 58], "66b4a8b2a17f0463f7427c0239106eaf710ea7129f42d184a58c50cdff614ba4"),
        (&[0; 59], "dda4668c44df722c5a963fbbfa1ff3a597aaeef5f2bf0ebd5bc28c88c1383f33"),
        (&[0; 60], "5dcc1b5872dd9ff1c234501f1fefda01f664164e1583c3e1bb3dbea47588ab31"),
        (&[0; 61], "c6e26c3e31bac75ea556356cbbd12190e29f277ea5f9010f8f88d5ab3363a2cf"),
        (&[0; 62], "1ebb2bdc5ce08e6e90b3ede72a8ef315e3e1bced3a3c458f69b6d7eeff9e4f3a"),
        (&[0; 63], "c7723fa1e0127975e49e62e753db53924c1bd84b8ac1ac08df78d09270f3d971"),
        (&[0; 64], "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        (&[0; 65], "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7"),
        (&[0; 66], "efbb03b7a7f6fd3c29391d4d0281e1830a85caadd831c3f04716faca4107a42e"),
        (&[0; 67], "1be2b3990b410ca4fb38d1f79019c4018cd8820b69618646c81d22dfcbddc802"),
        (&[0; 68], "1751ac12e70e15b4f76c16775cd329ae55973b612521dab2de828a5cdb6c8ab3"),
        (&[0; 69], "cd05c2283f62b7c74911008df6a66101d51ed5cb23e6b4b5c84af4bc60db0f3a"),
        (&[0; 70], "82fcfd5215175da9e65ca7c4fb927a1fb0e61f09d54987c368e8e16ebd9c2969"),
        (&[0; 71], "0805dcdc42ca47abdc3d8fe11f8e0c7a108602022f71ab349648cfdd30a75aa6"),
        (&[0; 72], "834a709ba2534ebe3ee1397fd4f7bd288b2acc1d20a08d6c862dcd99b6f04400"),
        (&[0; 73], "9c56f48ae9bafd205262034bfcc2232b2c63348cb723d681ec39f13409f990cc"),
        (&[0; 74], "d0800cd15f8b849823220f7a12fbaa665fe426ed1ddb13b60ecb89a5d412c1de"),
        (&[0; 75], "367467f43d580c3c07040a78c7890ae4262dad4778878f9a49d5f652c81689a5"),
        (&[0; 76], "f2c0d5456a983ecd12e314fcfa19879179fc8424343baeb1325457472ae85601"),
        (&[0; 77], "075561eff2cd3ad586776fa904f0040282c5f6a261f6a8fd6a0a524d14cd2d2c"),
        (&[0; 78], "5552748b5aeb500f57b3d1f4a56e4e9789198918c663e712314ea999026eb896"),
        (&[0; 79], "41681f90ae14d87dee5d37d19500fc21d85c2b3e7b0dd697a27c36d03e3606ba"),
        (&[0; 80], "5b6fb58e61fa475939767d68a446f97f1bff02c0e5935a3ea8bb51e6515783d8"),
        (&[0; 81], "6778c7c7b6b6c1c273e668169a7652a681da86ad62d03f7c5aa120405069feb2"),
        (&[0; 82], "10cc3c382b13ad9246b74708d03528d294522c558727bd2ed4a242bfb7cf0c3f"),
        (&[0; 83], "0080a9f7727726783617077919407ceec77865f5ae67d908b87ab0b42ef55fc9"),
        (&[0; 84], "4fea5e6a3ec5f5474a26d858bc77b6d7bd3ab864ea02d988683fdc648602b248"),
        (&[0; 85], "6a3a9301bb8dd782bb5c170bedfa73e9e7c60235e6e1840f14bd14b812127ef2"),
        (&[0; 86], "36e85b8ca5cc07b01ad98462a7f8afd1794a65455dc33ea47adcb9f50dfe5207"),
        (&[0; 87], "69a4d78bd3ff7e598bea7faf184809c5881d459e36dccbf1ddef161499c3e7b5"),
        (&[0; 88], "10eef285deef7a4b7c82b22aa53589b7833df29de3814649c772bbd5c832f365"),
        (&[0; 89], "a0bf83b3948dce6afe987c170a5cd711a3d65fcd5c70e3b7bbfeeb1578544609"),
        (&[0; 90], "988a09c9a6ee66322f9f274fe0ede1186eaf12b1c9fdd5f62152f998223521db"),
        (&[0; 91], "2795ec931b5b17c9e0e5e5adb2ce787d413ab0c2bb29cfbf554668fea090eeea"),
        (&[0; 92], "62b14867e4e79d50673d2f7474335229f54c478f56d2a910235e1953c6d29206"),
        (&[0; 93], "dbcfcc77f5774ed3333f3963eb84a324fd967de4d62c96631be6af1d6b3fe136"),
        (&[0; 94], "d37ed83de65b33e0a0d73e0fe3045ec685df14c0342d21c476910211a95b8c46"),
        (&[0; 95], "8542681424ecba28d65569c3be0d3962837fdf9d6cb770620108a86cf9e8d75f"),
        (&[0; 96], "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"),
        (&[0; 97], "136dd1a7d0a62859f2077a62b7673c5c712fb750604a15f5f6140ab2c5112327"),
        (&[0; 98], "30274f1a3e86d58c63c688e25ae4e34231a6f0cc07d6fc55c8b1ab154aff2fdf"),
        (&[0; 99], "4b298058e1d5fd3f2fa20ead21773912a5dc38da3c0da0bbc7de1adfb6011f1c"),
        (&[0; 100], "cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3"),
        (&[0; 101], "e08dd9962eedb16e12840ea2a977cc07bc5fa8d96259682edaa080573d525e4c"),
        (&[0; 102], "c419a92c7dce5225606f604f79d0d07009ebd882b5d5d41d234b71617b691774"),
        (&[0; 103], "37446575700829a11278ad3a550f244f45d5ae4fe1552778fa4f041f9eaeecf6"),
        (&[0; 104], "39f37f8d1931b3bdf767e7510dd69509fbf23af1f7654933d0a4d291cbdd4418"),
        (&[0; 105], "523c41464ee47d61350e15bc091bc970d73ae2d00bfe7a88bc7fe00ae6202c75"),
        (&[0; 106], "34dbd6bf55d0d075d666181d9278b8387482a8b5804e44e1ddaafe6876dadc15"),
        (&[0; 107], "a2fc9fa6e6b6d3a4b88353d579157843faa359c96cba77b815bbeeaf6a966a96"),
        (&[0; 108], "77133f431d5e12dd850002c0d3d4e0fecbe3a7a699d604dc8c5eae9976e1d260"),
        (&[0; 109], "b58a85e1f384420431f8db86e05ec571dfc7870195ea1b05b8a5fe1b8143f634"),
        (&[0; 110], "f23391587f1c9fc48eabd1e95f4caf16f585ef09941b7bc24f023d228e81ccd5"),
        (&[0; 111], "24b920fb2f49f521a4fce8f8d0bca1098aa7b380733f96fd6de736dca5006a2e"),
        (&[0; 112], "b5fdab78d8947eacc864bfeecb4d2100780e5afe1cd8efafb124887913ac49fa"),
        (&[0; 113], "951b1c95584b91fd8776e1d26b25d745ad5d508f6337686b9f7131d7c2f7096a"),
        (&[0; 114], "802bbf1167e97e336bc7e1d1574466db744c7021efe0f0ff01ff7e352c44f56b"),
        (&[0; 115], "23cd67852af04fd6885d2763266f2765b5e03c6ae3a5c1c6c95f7e03e10ec10d"),
        (&[0; 116], "5b517952cbe9c4c147bc3f3434f9d82409e76d09ea58905aefe7fb5415912d9a"),
        (&[0; 117], "fee3d3a17121f0dd0962d02ae385a9076d6e1ccc7b82085992ff41eca3c2811a"),
        (&[0; 118], "017ab4b70ea129c29e932d44baddc185ad136bf719c4ada63a10b5bf796af91e"),
        (&[0; 119], "f616b0d54e78571a9611f343c9f8e022e859e920381ab0e4d3da01e193a7bd7e"),
        (&[0; 120], "6edd9f6f9cc92cded36e6c4a580933f9c9f1b90562b46903b806f21902a1a54f"),
        (&[0; 121], "d8129de4286dc4fd245c7776b51d76aaa727956e8fc88ff928eb69ff7fc17e0b"),
        (&[0; 122], "1171666c3e0af069667251bbb8dbac52aeff187a6866daa07c597c813aa289e0"),
        (&[0; 123], "409a7f83ac6b31dc8c77e3ec18038f209bd2f545e0f4177c2e2381aa4e067b49"),
        (&[0; 124], "7b8ec8dd836b564f0c85ad088fc744de820345204e154bc1503e04e9d6fdd9f1"),
        (&[0; 125], "42d699d9e89e439804c0981f96b1a3fa7dbe42c6be1dbca6211c6faa4e0e2463"),
        (&[0; 126], "ebc47d1683f1e8b6d506bf43f07f93e64fcb54ea8310a90211336139a80e706a"),
        (&[0; 127], "15dae5979058bfbf4f9166029b6e340ea3ca374fef578a11dc9e6e923860d7ae"),
    ];
    impl_test!(Sha256, official, OFFICIAL, Sha256::default());
    impl_test!(Sha256, zero_fill, ZERO_FILL, Sha256::default());
}
