use super::{Hash, Sha2};
use crate::impl_md_flow;
use std::cmp::Ordering;

pub struct Sha512Trunc256(Sha2<u64>);

impl Sha512Trunc256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc256 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new([
            0x2231_2194_FC2B_F72C, 0x9F55_5FA3_C84C_64C2, 0x2393_B86B_6F53_B151, 0x9638_7719_5940_EABD,
            0x9628_3EE2_A88E_FFE3, 0xBE5E_1E25_5386_3992, 0x2B01_99FC_2C85_B8AA, 0x0EB7_2DDC_81C5_2CA2,
        ]))
    }
}

impl Hash for Sha512Trunc256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512Trunc256;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
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
    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); (1024 * 2) / 8] = [
        (&[0; 0], "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
        (&[0; 1], "10baad1713566ac2333467bddb0597dec9066120dd72ac2dcb8394221dcbe43d"),
        (&[0; 2], "ee30a3dfdcb4ad6546cbbbce99a4f6e42758ffb3781e8a47d2a7ff22f60a4b22"),
        (&[0; 3], "57635d1312569b5a4c4c26fd7b5df0ed403045e9608e9b14eae870588848e4d9"),
        (&[0; 4], "b5e076ab7609c7f8c763b5c571d07aea80b06b41452231b1437370f4964ed66e"),
        (&[0; 5], "fc94cb6cd9283825761d40bde79160fc8a359e8cf670dcb3d544cb0713095ce8"),
        (&[0; 6], "0e57ba616ed98b87bb4aa050f6d47526f6c73f303798d1e2267f99f145cb2ec6"),
        (&[0; 7], "4e9279fdcaea71d8663b53de0ffb214a407f5aab8c5f8e6db820b7b6d8639c1c"),
        (&[0; 8], "45ac134ffa7a54f7c40eeface107be5788b603621774295cd06e0b327a2baf95"),
        (&[0; 9], "e111bd7fbd1f8857017ca494367fad9b6c3da4ab8e734336c3b028be456a0758"),
        (&[0; 10], "786d2f03697d2807f4332cd8bfab4773c377d3f9bb6be3827d1d5ea81813c2c0"),
        (&[0; 11], "e8aafab2a1cfe053d8d20ff7880f052c32fb2ba65e6df94dbf64264093c8eab6"),
        (&[0; 12], "e90c1765e73c4e7d244bf17f385937193572de95137f852f024f397030b3d17e"),
        (&[0; 13], "598a5b43b42e1c6e3224f88e8d6ca049a99dd453356944092c46f7a4bdfb53a9"),
        (&[0; 14], "c447ac4ed2ef402b16289646aa3d1b30e55909344867f66914ba5dfcf9c99923"),
        (&[0; 15], "bcd0217c2b9aab9366b1d2836a998c73214e1de446f434238a33c438a50e9823"),
        (&[0; 16], "e41c9660b04714cdf7249f0fd6e6c5556f54a7e04d299958b69a877e0fada2fb"),
        (&[0; 17], "08e2fa44900e64a97eb33a405a5acbe9b805249f10ae70255c906e765e41fdc8"),
        (&[0; 18], "9fe40a1199f4dbe6dbe7a73079956caa2f4eef6ea9133caa6552052a8be1d2f1"),
        (&[0; 19], "beee357b9da2caa3703013a36d35dbb8272fc3f41bb7b8917d740293d729e3b5"),
        (&[0; 20], "90f48b3867ec82d19a4ed07be735beb7ff3aa1e3625a060d7992da85b722b0e1"),
        (&[0; 21], "ba8d4500b5abb73c5d247c747d0a75524ffbe3ae39cca836fb7a16f5ddde7091"),
        (&[0; 22], "2c3fff67a9f4cf87148832b762e9dacee673e885123355977f8d309346153f58"),
        (&[0; 23], "42759dea89acb5994dbdd5155cf54489b08656d780c4e3b095196b2493ce8c42"),
        (&[0; 24], "faa3d64b9471e4924fff47e39b79a6fafcf1b5bd5e7be0d29a7a40c0cdb44e9d"),
        (&[0; 25], "e715353523e747d9d8d04ecc80a538b975a496fb0e2f9b95a35c44a92ea4a552"),
        (&[0; 26], "18c939ac8a6e85c9b6a958ab30a15df38eba91d1c7bda57cfd2a55f9b43c7d11"),
        (&[0; 27], "6229aef2bb1018f4fbd5f800bd2cf279cacdaf46f12fb547ff696d902be9e990"),
        (&[0; 28], "8ea29d588145e18a923a6d0973b3bb4405db8a747509a464af9406ae71ec54f1"),
        (&[0; 29], "468406bffb860f7f3afe032c810589be7693231a1559cbe5ddcf15267ce892a3"),
        (&[0; 30], "b0de5fe96066eea1e396d8cac95690eeb3268f413f7298931603761820fc5d35"),
        (&[0; 31], "e99abcb360c04bfd77f4db270b0a9426e9d89ff2d91dafe3cded0a06710b30e3"),
        (&[0; 32], "af13c048991224a5e4c664446b688aaf48fb5456db3629601b00ec160c74e554"),
        (&[0; 33], "980baaefa11a71b7e4e9bf1d7f26874047a353f59e60eb78a464d2e0655ba93c"),
        (&[0; 34], "e28ba588f2214c4011a549ef3c9b2f8b6db0bc6157015ad860f4ba7d8f634c2e"),
        (&[0; 35], "21d89271b0cad997565e6ef30d3308d37a111083ef9fa02ed05ec14a72e2b929"),
        (&[0; 36], "19818444c98cc946c62533b3dce06b5a73333f42d86f7f3aa39f8f945bf5d0e8"),
        (&[0; 37], "687f28b47b2367a5b3099221ae73ddb162bb40e52f0033bd29bab12688fae112"),
        (&[0; 38], "5168e3f02e0744ee24b24b95dfab1213243cfd2c7a35d220805e87ced2dc53c4"),
        (&[0; 39], "b2b29587de7bfe7805f70f7248041d7c62e8fe9eff2b458254a78daa932f06aa"),
        (&[0; 40], "22b93d195c8e20cc470d8ff1e03af595bb7466dd273f94be6faebad08eccf3cd"),
        (&[0; 41], "01fbc95b5419a6fba74f6c83e14d26b2200a82069a2cbcd977e8737198525622"),
        (&[0; 42], "62742cd19697d48f5f271604646e80b7f392d9566307124618565881469644fc"),
        (&[0; 43], "a6b7e725038f4507d019029460c19b7e6c65f2d0eb7b665be901c13a6307789b"),
        (&[0; 44], "25281e7af089d15e4c8ad0ca4f5eeff13b5beb8442c430fcdc374860e04a3223"),
        (&[0; 45], "b74350327568bbab49cf38af5456b06a6651c5293da8e0e1399be8688dbd3996"),
        (&[0; 46], "2e57c3fa38b41d996d31a1ab8d2a70cb3398b87e4bf04b03a448ae1e2f695f62"),
        (&[0; 47], "dc0f7a799de0ae91c70ec44236ca9a4cb53b00c1d4a72e955e8820ab7825e6b9"),
        (&[0; 48], "c9ebda2d41a46b8212184d713eadfe323e3bd69d9b38cfed151c115abf1089ad"),
        (&[0; 49], "c25daaa77ee830775c1f86f8101272270931626763c23d4f31176f1cb11b7196"),
        (&[0; 50], "8e473eaecef658cba91f2ac96e3daa6b9230da992a0d1a6cccc96add05840e6c"),
        (&[0; 51], "c318f6ccc42b7c98d18bc53fe4d275f93663c10002c82e0f6fd8e3334056d127"),
        (&[0; 52], "55c9861be5cff984a20ce6d99d4aa65941412889bdc665094136429b84f8c2ee"),
        (&[0; 53], "2e2abe099ae51269fda4f1fb16fd029bee8455bbaff9a49e058420dcaeb2e3db"),
        (&[0; 54], "d3ec4fd845db5d363106d091e325be2894e8097c52b1ad38a051d56a33ff8c41"),
        (&[0; 55], "737d8ab6313fff7726d63276d2efdd1efa0018fd010ea5985c289c657f91ed55"),
        (&[0; 56], "84b2f62d5eea48e0a401c2829684ee74d8b4abcec090e2921a62c5b8e8e5dc53"),
        (&[0; 57], "0b07df69dfff6424a24bbfd3b841ec5a760824e96cd9e84a965fa037420d8587"),
        (&[0; 58], "b6960fcc3dac27592c92b2abe0bb953b5a799c440fee5fcdc70c76ab246f253a"),
        (&[0; 59], "12adf37f434cc73efb34b5480d03cb68366f443b24f4522ac243c3642db69279"),
        (&[0; 60], "05300dd55cf876b38cf536de903578dea0609961c2a456e2e755b56c417c7f44"),
        (&[0; 61], "8a4e27aae1f785dbfaedf03f2bc981adeb84693003b9f74bd793fe5913c529db"),
        (&[0; 62], "05f5a66d7669faf407928c60d21b8e5c5df0a8af8f845561f5b248ce4b2c9ac0"),
        (&[0; 63], "99ad558ac0c5ac1ae52a31881bbc2e46118a7d6f2aade3e63f8276db94abb3ac"),
        (&[0; 64], "8aeecfa0b9f2ac7818863b1362241e4f32d06b100ae9d1c0fbcc4ed61b91b17a"),
        (&[0; 65], "e3d3a51ef807d9029de3eabec4e50b6c9c38f44f390bb220addea64e42432f4e"),
        (&[0; 66], "985af119aeebeaac15b1ec503f4908af846ca09e73b9f5366d2692c8a1494526"),
        (&[0; 67], "5963f08ff4c25f6e35763bb201684ff450ca7302a82663c0e93b25d01d788638"),
        (&[0; 68], "a88c440564fc9c3c689ed928bd6c3f69ab1035b8c223b0b9aee7e78c7a0a0bbc"),
        (&[0; 69], "5081d078980fcea41dcfbb45add22cd0d47ce7d19d65a2986f72c3cffa2d4620"),
        (&[0; 70], "5ab2add52e0a4460d081277727ff04f8f42177f029ebf9a07ddac18785ac62c2"),
        (&[0; 71], "ae78e496b5e14648d064c88ec6165782776a13078627200ea146bc79be48a578"),
        (&[0; 72], "296e48e1b5f8937bcc8a75a5fbbe43c936aba9a6b256f9cdcf0a07bccc6d1588"),
        (&[0; 73], "e145b7194232ccecf2a10293138bfa01c272cc5073fd0d284ec5b779fc61a905"),
        (&[0; 74], "622cbce767de012df871c7004e2d61af2345542f57c21de3c4ff49ed8b90ccb2"),
        (&[0; 75], "c6dab4b1b6b037e3f286d1b4e23e33ffa1274fd447d175987a1ef0aa5b0e8b9b"),
        (&[0; 76], "880be9c973ebb97a85dc58f083f1a6472c374388a081f8eb5863fb4d7ef5b3b2"),
        (&[0; 77], "1afe0188829337a69257aaaa11c8a490d5e0c9a1d709745d5818b78690773832"),
        (&[0; 78], "8da3f522644e3b2273fb3bcc27a524c3f076e6fd054fa9af189bea24313018c2"),
        (&[0; 79], "80082a2b36ec9b48c6e0f561389fb112ce964de5444bbec3e93f0bbb2bce68ba"),
        (&[0; 80], "3f13c8d427b5bebe84e73447c8010791d4c12fd57a6c925a64ec645b6ae2d617"),
        (&[0; 81], "50a348affc9b3e71a2d8e007cba7c1dfb2c24c9e26489cd3a77e6f57d9079c14"),
        (&[0; 82], "023af1ef1b738f0d39f4c71bd4e46f0db004f79ba037141649ae41937b17950d"),
        (&[0; 83], "041dd4bd37710c57fc95d4d6a4d1ce5df74197efd1611e7741d522b296e6fbef"),
        (&[0; 84], "91a5e12f234619b53e1ce3a7748901f0339c94cb0c5f946e8b74562d65fa33fa"),
        (&[0; 85], "22b80f01e70aae09c8286937aa23560a0cfecd70f739fb636baee0c56c45a1ca"),
        (&[0; 86], "b43da9aeeac2b76d9af675fb265cffeecca7698fca40879b1901476887ae707a"),
        (&[0; 87], "00cedf49c4bb28f96e757b0b8c00c58c50065451443c443b35207081987e2520"),
        (&[0; 88], "912fc83e356c8f93e943966e85736bb2dd564c50d4dc0a7a50b68481618856a9"),
        (&[0; 89], "b7409e52440a25c5701810629153b782ae62dcdbd3574e00fe7101629745b182"),
        (&[0; 90], "c55b1a6efffca00c08746d096b068aa99b72d9ac5aa01d537681b2a13986d0b7"),
        (&[0; 91], "e58069955979319729afdff72467d5b6e9e0d50bb65b83845b1b10cfd00830d6"),
        (&[0; 92], "86cb2d4a345cda4228c3ec28f2bca6f0d14467fad795da1d3729034e1c7e5d6d"),
        (&[0; 93], "7844ef1ab0e67aa5d9d4df22c6145509b705363fc9f7d11bdf86ee6be1fab986"),
        (&[0; 94], "bfde93ca23f8d54150dccdfffbcbd3f08cbd6c887214b35da1dd2e75037c438c"),
        (&[0; 95], "4e36ba3cb052437f2bc758c57babbfdfc2c8ab7e60ec706595bb188d19ca7fb7"),
        (&[0; 96], "c279e7ecefb1844daeb508aade7e080630454c0518442c480d9602039a275f53"),
        (&[0; 97], "3dca189d01fe85668a389fdde836eb65e3180d04c895d521f8b12f538712a97d"),
        (&[0; 98], "2dc0158f4417542534003377a621e6a4432990c92fd695b9a24436e2e7f3cb3e"),
        (&[0; 99], "0b71b048f63cff47b3876f2d912101c694da6266c8486ff77d3257afa847caa3"),
        (&[0; 100], "5e5230840a495a2e357df718edac9b2cf6de2ef567e51c1e37bede10ad69b8c7"),
        (&[0; 101], "68c1ee5ca3cd1851d88fd4f94132080dde30bbe2691a542cd8ca53585e98b578"),
        (&[0; 102], "e124cfebc4b1e3f3ef8dfd69454ef10d689988f3b0368d1e1942bf3f5b317a39"),
        (&[0; 103], "22455485d5b941f2beb408bbee817ced6d8ee43df02cf2ad265e9e92fc711117"),
        (&[0; 104], "6b1b2cb7b3c69219860cc96c79462e44c306399c7a5112e05285666978ba776c"),
        (&[0; 105], "e2fbcc290b4ae6cbd8eca9282f5f83d68971c758631b959daaf0d627a3f60d36"),
        (&[0; 106], "35c2348dd05353d9875d88368063e2a15563f02f7a08ce9cb56f0c86032824cd"),
        (&[0; 107], "33501d36c6151b3bdd58b42533c911d316cb10472787586b347f1f1bc37fd3fd"),
        (&[0; 108], "e1374628fc21f3266c212b1fca11e2e862d2c7802c1957a8e8c3cff5d2b5ad45"),
        (&[0; 109], "63e831a2271421650f7ecc556e2d1a5bd09364efb01ecf85ae4cc66032e2f76d"),
        (&[0; 110], "24a0fd021da1ff94759a4ab9493bdf136724df810894e4528abbc964e2353a86"),
        (&[0; 111], "5192ee5471d8a02ffc34bce87142df77aaef777dde522cc171af66e95a006a15"),
        (&[0; 112], "ae534ff4eb3f2c1e11a16c566148e7aece987752797a8a555b75fb64ff58d54a"),
        (&[0; 113], "20ce9c21bb5edbffae72135f58bab9fbabb2754614514a72888995c120556552"),
        (&[0; 114], "10553bf412f9ec02059bda86c139bdb45461a59f9be64766a6c53b72664e740c"),
        (&[0; 115], "c2fba28e1e31dbd0bed84316f7c8112950cd0c7570401c467a76235c4d5f28cc"),
        (&[0; 116], "721f32795bb09c530287e06c8ce7ba245d6374c47a55fcbc1b8b3ac943ec15b5"),
        (&[0; 117], "befd1fb335b7d1dfa03f4e70a1a8f2f932abba6b8fce6de33a253a736716a331"),
        (&[0; 118], "de525b82dc55a26a75195b3b2cd7df47a8deebadbd9fd5b7b913ce39214e2740"),
        (&[0; 119], "664ad0705431e2d97e42ef84f5dd3e903e7e98c1296d88540c9519c38608dee9"),
        (&[0; 120], "067880a5256c0584cff10526ed4c9761e584bf0ecdb1b12c2ae7f1dcedaf3dbf"),
        (&[0; 121], "448a66d077ab9ffbf222b846abca84fac840b3a6b8bff4641c22868f4c2bd3dd"),
        (&[0; 122], "2491eba0847e4daf54295002b1f18856582cf1e2ab6e9552847f49d1bc1e1d2d"),
        (&[0; 123], "e557d0858a4180337c1b6d59b85f87e2e72a4451ca0498dfb4a62814b78646b4"),
        (&[0; 124], "61b0dbb4df16a767d6ea371243f4c0a42a057f44081ff6d549c28c41abda4523"),
        (&[0; 125], "2c53c54518987d8b104e2fa83471433546c26674153997edbd761eac45df0fde"),
        (&[0; 126], "c68271938481f7a6d79822bbb39df3c85f1d6c37d64e8cc5b6bf393abfb0b1d3"),
        (&[0; 127], "d4d757d87ef77e82a4fcd155a79ef36e03fd27a05a2f569bcf437b862b2b53cb"),
        (&[0; 128], "fe3d375e149b888e08e2521007764b422d2cd6f7b0606881b7fe1b1370d5fa88"),
        (&[0; 129], "5ecd64b7fd75a64f162e3479bb46ea02be6d5878ab71481dfbb354335e804f7a"),
        (&[0; 130], "91ea1d7f040c24e8e9537a9a7da6614c08ca1a38b4fd3a70b109771e5667e707"),
        (&[0; 131], "44106cf3a7aa2a52a188982ee1269b4ac18eea891c0da3d2974f03280e2ee4cd"),
        (&[0; 132], "4c207233faf3defa2935c41574f439ebbc83a6667afcf2055a5a1e17e44cf8fe"),
        (&[0; 133], "82a395ec8c011ec0d74ef3d5fdb2420b3a928ca879acde85bf050a939fd3d148"),
        (&[0; 134], "6e383a0ac28d7f070d652089c089fef37283fef5b9d56f6c2dc0357f215118f7"),
        (&[0; 135], "a00c6a7639675060fed6f4c643fd778cf6876bdd7f9311edd112736c02fa7ec2"),
        (&[0; 136], "790f4925ade8ae7a96c3c3f421a38f34145988c23b25d5113736c9658e05408e"),
        (&[0; 137], "c79cd45a5c9474497db224b0c5dd8e2267ffbd83ac60c73b20bb1e9af58884bb"),
        (&[0; 138], "694b8deb627c8ab91abf8dc4d013b6052367bfbc0bc58b828f49d1d22ba26ac0"),
        (&[0; 139], "dc74f68145e278bc42c6bfaf3b01c4ca76ddd3f426006be9c276846b8a51f167"),
        (&[0; 140], "bb780f9526eb0421b71e38423eb5d4067fdf4c855530626dcf64e28b0196cb9d"),
        (&[0; 141], "466bdc86474236042b6e1613737dc6fcde1d730647fd581c4d1ac98331bec9a4"),
        (&[0; 142], "1d348d5058cdfca0d79e72759ab58fa308e5c773e84d9a7b959ba47abb23b0c2"),
        (&[0; 143], "79585a4a6edd03fbbb75472749aeb7dc9b690bb4c0c8a5cf053f2998cb9dd5e4"),
        (&[0; 144], "114fb2b0ad042e9e2fa6ca0d01ec2d6b891e3ed1064ec40e31737bf996011f13"),
        (&[0; 145], "1b84c397a465a76d726641c59582a2f8b4a62dae9c8f2a94ccb574f0fb0d2830"),
        (&[0; 146], "807cfe7f71f35f0b52fe888e8f0428fd68be2a5aafa900dd501c1a611d7b7155"),
        (&[0; 147], "620abc0ff86192eaa3c5ecacdedb05ee725f6c441125168af38da911f6104b07"),
        (&[0; 148], "cac5e48f0b420e2a419109e24539b39323d7bbdec5c95ecfb5c1eb9edd38da91"),
        (&[0; 149], "13d897a6cdf813b1f0cfc9e95dac734bbbe7d00af4d5fc2963eb1b14694e4d7d"),
        (&[0; 150], "896907d96d2627bac11cbe3ed5553232b2ee5d4175085ac4f229d8afefc25065"),
        (&[0; 151], "c29eb0e0554bdfe78ffcc5df0221136369c76d0e9efbc2f571885a53f518c868"),
        (&[0; 152], "3fdc85c7f5b6591b1b0f1b4f2843018067db76f932b3a0f78bdea92b4b0ab45a"),
        (&[0; 153], "984eca29d6db4a6abbecaf7c0bc1823c345ec6c0196148ebd4c7c787eb3f1526"),
        (&[0; 154], "27e8edda3c66b8d84006817becff83393ecacd0310ec9eed53b2434525438c5a"),
        (&[0; 155], "2a8fcdd20ca48fee33a854793b1793863c5a50a3c11ba7f48e72b48cf4c87d19"),
        (&[0; 156], "a3161c6808b209bb4ce67f3085bf663776e19e03ccfb12d094d206b4cfad349f"),
        (&[0; 157], "20cc1594eae99db90e425e967f381b0f81f5bf8f84e7004d1c5bf32e60c35577"),
        (&[0; 158], "88744fdb01f1656266ccad163b5b7ef532f600f1f89796a2068801c362e185e9"),
        (&[0; 159], "ceb230fee8dffc564d2f130ca0768442431f9f28c9af94f624931a944c27f85f"),
        (&[0; 160], "22dcd4337e296b8617321f641c6a24a916929c317dde15a612c43ef4e4c403f6"),
        (&[0; 161], "d018831063e48ac00c97b4023dd3a5c2932e5d449cb9a8baf1da6d25b45ce871"),
        (&[0; 162], "bb1efa67f47ac2fd321243d30948fd0e93a629a1f8678ec5ff5f7f318610b55e"),
        (&[0; 163], "283c6c70b5f094a0f4136d0e564c439a803d09db086da1611605c2f5f23a0ef2"),
        (&[0; 164], "cb198150744692cc3c075ad8f3d06f2967927f7adc6856f953248f30bb5fed59"),
        (&[0; 165], "59f2ae88f82844611cd721c1f876c61959ee33a16c03f040d4e7c1aa8d56e631"),
        (&[0; 166], "061465a4d12a924fc5cef5e65c9e76e81cdbf90daf18c850d9435a9ced64b427"),
        (&[0; 167], "13f7eff2b6f54f9db1f415c923e8d168c6db12a3fd264856360717298c21c80f"),
        (&[0; 168], "5ffe54486b7cb01327cc504f5b937112f80cdb224217189581a9193a1d15ea2c"),
        (&[0; 169], "69c5ccec5f3fac8c70c09c8d923689b3c49b73577d6860ec74b699e142026d97"),
        (&[0; 170], "0abb78cd409003bd59c1c492af32b1caaa9c6520c870a1104bce7b9bebb15a66"),
        (&[0; 171], "09451475e37ce7ecc528d780a4d57f3fedf2d803f4ebdd510a30107896ed6d1f"),
        (&[0; 172], "585f225e3865719ee0db839993710b4c0378a9dc79b1b6660f7051e4d5d63614"),
        (&[0; 173], "9e1434ce775694094b227ac843e1f76c6b667307f3fdcabcb58874862ad29b3f"),
        (&[0; 174], "c8174d449195950fb56ba029ee6b1ce0abcdc1c85f0fe28a0556f1c2e079858b"),
        (&[0; 175], "305cc83d0e0fa6a4a29d9dc0601e58a4e32087471ef208e5b271c59f34b8000a"),
        (&[0; 176], "0a92fa89eaa9e987d6fe9d4676c3f9b496861c9c6a0dc6e0dcbd89aa83ad2597"),
        (&[0; 177], "f36636a5e935d41be0098184090efc781704ac2a1302bbdd33cad19899fb154e"),
        (&[0; 178], "83f9f55e2b8fc0353bfeffe763d2f9eb8274c376da0eb1843f64bdd12dc0fad3"),
        (&[0; 179], "ccfb6dcb57a9e0f0a1f92c96f787cc80e715b027e6133590ecf3ea62ea353394"),
        (&[0; 180], "3e217d397e80748e21032c7adb69db441d5da7600198ef7f6d9403d32702e70e"),
        (&[0; 181], "42cab7e76e140b64fbefe7e580cf7f1522f47c1a6378b53a0d5792049d259242"),
        (&[0; 182], "9c0de82f585f00cfd66e5a5d3e5facdcaa207981d57bfa34620fd6f95f0d1b68"),
        (&[0; 183], "264da4ec3c59585861de54268e45f08660228843d751a48897361c09328fd930"),
        (&[0; 184], "5702738dae6777e71ca56d5fdd5dbdef01b6d2af95aec8ddac35c25067dd7763"),
        (&[0; 185], "fcff94367f73ff8b7b7e005ab4dd4b2045d20cf980bc3229e4e660fcc3b46d5a"),
        (&[0; 186], "0c047f425540b2e0cf5710ac37a4e92aaab64a8de84f3b507a027545498c6ee0"),
        (&[0; 187], "c736dc08203d56a0335370d5488476159a425334cb67342aaaf739e9b7337ed5"),
        (&[0; 188], "0fbaea4978ef76a34b08f8ad87598746125a56e2da83303c534a0fafabeb9f82"),
        (&[0; 189], "aba02fd1ee24b6d07eeb98b2bae3eb65fdd535cef78e1feb3416688a5736fe01"),
        (&[0; 190], "108ca32511e1e64041f79315e61e5c08a513a9ff0eb8078b5c5baab284a59edf"),
        (&[0; 191], "c552061cf4482d72916fe1c79e4a0092492fce8e86cefc95148195edbef5a3d7"),
        (&[0; 192], "b6791ad72cee1b7babcb4a3cd1c71e6b71225560f038bd296084f0b00d9dbbb4"),
        (&[0; 193], "da817f35eebc8ba425512b0cb87efc60f5d8ceb6d6ef5fc60347372aaba475d4"),
        (&[0; 194], "8bb5a500e834651b66102903b7cb941d0eae84d7b657129a0195f047476052c5"),
        (&[0; 195], "fb6008da7660bb2a4672c9abca58a6594cf93cf05f5ad1e97f549b0f71306a71"),
        (&[0; 196], "317e5d5f9c3fce524d784b66694b605f045d4988e33afdd06b107cdf3a152316"),
        (&[0; 197], "8ab50b37c9dec3ac3b706a9958feb5b56812bab954a9ccffafdaf2914e8deb78"),
        (&[0; 198], "ce26153fb4eeda0be39b3f0bcb0047e04fc5fbbe93cb717576df715653157dd5"),
        (&[0; 199], "afe2b5ab4d3eee6491f6ee3c093ff62ce8c9b384034289ce1cc752f808f1f3ca"),
        (&[0; 200], "b59fd3fc9f41eb7a8c758ae6a008a8f4dca3f55c09109aca3d012b8ece42010d"),
        (&[0; 201], "a87e9fceca0003f864cd85be4338a0b5ee9a1ef5a09d15cdb1e9503bbf20a046"),
        (&[0; 202], "95743d425286b7a27eb67560819dc5fc4749e502aa56a30962f5f9485ca03ec5"),
        (&[0; 203], "266428c71eb0bfc0505d68b37a1491c055abde039545acbd3b7117dfeb008061"),
        (&[0; 204], "2cff246bef43d1488f0f09ec35810466ed38deddaf9159a9ef2995dac9422cba"),
        (&[0; 205], "70acf524ecb20c9dbab057572c1b4523b58a270786523246cee6e1951a1197f8"),
        (&[0; 206], "d7db3f06a9b189556179e96a97eadf4ec14e5defa38101d95b43601aa9dc6480"),
        (&[0; 207], "953ff44f49e2e14f9b8b45c0353f61c6fced472e7df09802216825c363b34d2d"),
        (&[0; 208], "da450c35db75fb25afb06b70e39133847a4f3a988752011cfd17fac4cb9555b8"),
        (&[0; 209], "db86f32ff986c76eaeebe89c7889e3a995c6f1cd39816245a4ea0de58ff1aa54"),
        (&[0; 210], "94b55d59c569c9950130dcbcf891b1333968e91789b6597b180d07d67596bbf0"),
        (&[0; 211], "0af941967edff2684a512ff34fd33bbda10541c703482aa2acae4c96c0d85252"),
        (&[0; 212], "420563856ce7114ed9ac8ca0a2e6b5857c0060e85fa1c107ff0225acb2f44d05"),
        (&[0; 213], "a0a3b2c51257c0d69874abc97c917ca30cfab2c2e98e97c7e76ba31369636566"),
        (&[0; 214], "f634b101e59cd71c81d41a2b14d2bfb6ea52d5bde5a6817c110e24024926028d"),
        (&[0; 215], "ed7463dc58bdc8d61d0a3b2e552912eb3102d6e362aa5d88a932de15ff269a99"),
        (&[0; 216], "4f68f56e4f8b34fc5e353c35b9f73f0411230f1fa09ee1076eb1a7db632e9869"),
        (&[0; 217], "2b356c6c02d21b50d9bc8e5d71eb5c417cfa49f8060910e290b99d7446aa1a54"),
        (&[0; 218], "7940c2dd79c2b464c8cdd071e12092e6e1550f78ad630397135431c03045fc1e"),
        (&[0; 219], "1fc77879cc9c2589da24e0c1f859c83ec57316b865f01932c72cb438fdbc7617"),
        (&[0; 220], "933ded88b0f70abaf96d4658ba8ca7ebf1f44e0a5139b55e543748e59fe6c651"),
        (&[0; 221], "5ac37b5843573f015adf635094ae1fa4ee0bc7e1c8c7fc1b4cf8fc28438f355c"),
        (&[0; 222], "a8c8a7481402153dc59b719734b2f337f1f79027bc5b308b3603c38d9939be4a"),
        (&[0; 223], "ae810113db94e2d27a3600b7099adeef86786ea85f4691cbd76f0865d5280fab"),
        (&[0; 224], "da25f5e695549296dbfc85851b6d87c064d1b6a7e35593ebe012725a71d55815"),
        (&[0; 225], "02aea2b9eb14778ceb9d356b9832209d9b0017d0ed85523aa9311382ee1d9dd6"),
        (&[0; 226], "5530a49a675ac7235fb9e680f7c7cdb3588a86b0270cdc6d4411af48588dd487"),
        (&[0; 227], "ef7b65d9802b3fde5015512f49bae8bb7c5cf38786a6d3bedff8c4794ed76a29"),
        (&[0; 228], "92c7b3d1ac495eb76f3ead6afb02d4164a7be6d8e74c7902a042e1e4e5c104d0"),
        (&[0; 229], "fc3e5049e5d31437d1ef0fcce054791f5546db54f5e207f56fe205099a1364d4"),
        (&[0; 230], "d0bf3b66d897aaca6035622ffdd9f6e071ca124da2f7d7bd6babff18b1751613"),
        (&[0; 231], "7197251faba70a64e08e8a35bd5aa424a9033535ed3a0b42b51351f72ac54f3b"),
        (&[0; 232], "0c4edc7ef68bc5e5fc2b7f9d06f334dd35ffdc4dce610904333e7c88124adb9e"),
        (&[0; 233], "a57ce827fd299796f750f84b33fb8cd48994d557caa1bd59bad7f2358224a327"),
        (&[0; 234], "57a3ba6bbc7a25c4b9187b1fc33dd6a4cee691bf9748fb552db21717b9a8f23a"),
        (&[0; 235], "ebae1437a800b9fb2fc872e174553b964e7b0a80dc8000d5cb23b269bda22e29"),
        (&[0; 236], "3f795feda5e96365c701c91c5b6e65938188ead950c0d84eaa22fd61c38da24a"),
        (&[0; 237], "d43177e594fd4e313079e8bc21790be16b7342c09aeb335c8b742739ee8caae8"),
        (&[0; 238], "1f08c444748620929a07f405b6f27faf6f29b4cb4b2b700de5f2bc8c4d048db6"),
        (&[0; 239], "12319a738986f2438213edd5d302215b5e540334b1cfa36ad5db222d6528d633"),
        (&[0; 240], "060940e1713c77106396fb9fc90cb9744f0ddc874dc9b45533c39b0330b0b5ef"),
        (&[0; 241], "3f8ed5002e970c5f828292fb0ca080b34c77031c176018d58eebad1c84f11c4d"),
        (&[0; 242], "698a25dcfe26afe85cc59ac05377c0e94aeb8c0f0db45f7f2a4032c645b3c8c1"),
        (&[0; 243], "c8ff802825ab818f0b52aa424cc5004a5952d44e94473913088b3adf309346cb"),
        (&[0; 244], "bfbfff34e42637ace63bac3e4146be97d6c0256ada95ce9c33a03849a43fbed2"),
        (&[0; 245], "e5e30b8de0aa1d9498a3d808c86c6702bdf53194355630e1e1ce7986c59ed0a5"),
        (&[0; 246], "0b7e41041673cf414e361db337a67b842a7c88ed034d57945adabd567eb229e2"),
        (&[0; 247], "9347ece0b26674d2eae64a37013f901d8ce3e25b7aa8385647e806cb46463045"),
        (&[0; 248], "03ed2f144fa4aed4298f854588c172e454531658f02d7742e83ae4a6f2099443"),
        (&[0; 249], "2e781dae6a616284f5009774cc7a5f776a9e4b29ffb695279ebfedf9c51394fb"),
        (&[0; 250], "e3b4f8d5812401866bb7381114c26a1b874447ebc58e8b2739eedbf6ad025315"),
        (&[0; 251], "d585bd3fe80b1fa27950685180af96a864d33b335a33580f39f0bbb5302376e5"),
        (&[0; 252], "7c4282c4c071ad7a0762298cd8435bc1a914a22cd6564f221a479b519642e5a5"),
        (&[0; 253], "0681a510ccbc02e6c91971053df1b8bae1930e4a247ed06bb1648d6434238ffb"),
        (&[0; 254], "72541396da254aaaa0d871e413f00391deb02d56dc9dc9eba350b58862717a69"),
        (&[0; 255], "1a25e66e8d6f96c1fc968ed9cb7439b061faba35ca3198065b2f982fca0795df"),
    ];
    impl_test!(
        Sha512Trunc256,
        official,
        OFFICIAL,
        Sha512Trunc256::default()
    );
    impl_test!(
        Sha512Trunc256,
        zero_fill,
        ZERO_FILL,
        Sha512Trunc256::default()
    );
}
