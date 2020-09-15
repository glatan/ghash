// Keccak-512: [r=576, c=1024]

use super::{Hash, Keccak};

pub struct Keccak512(Keccak);

impl Keccak512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak512 {
    fn default() -> Self {
        Self(Keccak::new(576, 1024, 512))
    }
}

impl Hash for Keccak512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x01);
        self.0.keccak()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
#[rustfmt::skip]
const DEFAULT_TEST_CASES: [(&[u8], &str); (576 / 8) * 2] = [
    // Generated by reference implementation
    (&[0; 0], "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"),
    (&[0; 1], "40f0a44b4452c44baf401b49411f861caac716ba87be7d6894757f1114fcec44a4d4a9f44bcab569fabc676e761fe9d097dd191d5d9c71d66250b3e867071553"),
    (&[0; 2], "b8a05aa89da82f286f59413c811918792150fd310d3a050845dd8617f8c4cb9612793ddaf9234c7506668fcc8809f6b871b4e193212ad551f54ba1cef79c38ff"),
    (&[0; 3], "a6fe4bf0b6e03b7688d80d7fb2ba82f9d16d084cb5ac724f15a04a14edc905d6c7543da10daeb326476de10f75ace1af3e0e5cf1556408b0fd5c343bf0f1d322"),
    (&[0; 4], "504ab73753a47f9cca024d3e57f3714a1b726a77367d526aea69e0c987a36766789ee746d33091333627d881bf4352ea6d4560be4acb05e581e1a4bca9e542ba"),
    (&[0; 5], "ab2b50ac47974d122f4dc9aa0d6dd540205d7b9b7519049182c6852a76ef37cdbadba0c8ed7019a7bf4510176363df8b561f784472245bfe3c9b5c75e5021d2f"),
    (&[0; 6], "f9c1cbd4d4efca78b582c9780c01c677eca1cf1576ffccd98e0d1c42d2bbf4f45fdf50997015647daa972f68b70e7412ecbbfe24c8cafdccd2cc49e62a3d84ec"),
    (&[0; 7], "96f7f0d7cd34328fa112d795dcb86a95f693fcdffb5cfa3e5de440002d65634511e973109ec57e0c7d9f7fb19782281c0f1f38ba5c05b76f83ebf70de19e2b57"),
    (&[0; 8], "0715bec05663677b9e0da96fd64ad443eedafe81a104ebbaf01f52c2aad94155514280397d0f6805c526402f2464c81dc9dccfe0a68854ba6e542e1e459441e8"),
    (&[0; 9], "fb2d315cf90dc3546c7a21d6c41925a3dba6195760fa1972b79d18e26213c136c435d6dcde6a2191047f1df02c0a8c7a23ddea8f51a2ac2cb1dfa304dac17d24"),
    (&[0; 10], "d51e75175c24cf828fb70f7a5c509eedea9d28a1051f97f1f91a4ddf5e67f2b24b952cc1f653454a28e084317b30276e9af4b15cda9849519de2c838ceac1636"),
    (&[0; 11], "9b8aec22bbc2e285eb7a4723eee290f61084aa5de312616136482314046902c4bf58e0a15dbbd78cc4abffc8e85c10b9dadd7c5559da30753d16c7f44c6ec168"),
    (&[0; 12], "591a0d2da82853e45bcf17345dbf8cac9fcb666d99606fc7969905fd6bdd57f3e3ea329d11231bd48f7304a2f9c2ab0c65e7b8617a10de78de15d7d138eda89d"),
    (&[0; 13], "206113519d64492a5573860e5332bb2a84bf7db8f6e562d8353c0a5b58c7b3ae9231666c86e0bd0210c22acf4d06371bbb4d44c2d0bdc3c9bdca8a672135ea7b"),
    (&[0; 14], "f96872d312a7e15a33e39803efd52e1c9d4c948bb19bd1bccaf99171b6472d985826fc488eb3ad1a13389f081e30eb26071b09bd110726d3f68308f64637b334"),
    (&[0; 15], "82176db0e9155e6c42994956daedf5a79d254f9f09e96ef3c2d3754b7bc5d4ad93c52ddeb48dd429453712fd1fe6a9c6239d39d66c0763be292507fcd6409333"),
    (&[0; 16], "13c205ec4a3281f0821ffaac2386bd4068a50eb209df3a264254685138041c480f6300501601eb4c2bf78e6cf2faafd3fb750210788d7341d6a7f6f4202ceaf3"),
    (&[0; 17], "3737d1679386dbd1ba7c2afa8962e99683a57169b070d91a1a242542aeedce858fbb807127566147de3c4cf72ae15d3ff5f69d92b430d7458271ceee11cee96e"),
    (&[0; 18], "09f02275a7fe64c3bc4cf0746bfe172080f56842594689b55debd0b48e9f80e9aa5772892f69e0bb7a230b25ee61d708bd3a93bc3bfaf8ab89bb15812cc777a0"),
    (&[0; 19], "ddba38eda92172fce04e553478b6737fd8562406684dc85b4d2bcff64bcdc9cf2eb97c4b7f9015f4a15c301066711b611272962d436ac60ffcec2f5b0be81654"),
    (&[0; 20], "f1a125fa0d131aa3dc5e727083ebccec96ce6a8f0b45c9c0fe82c3634d374dd1f1fa1409bb8b4ec279517fc8018d86f9bcb9ea64ebbc9f62ad7f5fa278adb9b0"),
    (&[0; 21], "0257dd86a89cce7ba206115609f7f577507258436d3085324075512dc559a689cf1fa2560daba5f0f2f1137e2726638f63129f11357f56032adf10a20a52304f"),
    (&[0; 22], "8f1c904cc3a15bf094d442ed592367f69a04b9d01e6f8f6b7104082382504b07312eafb83ad0c246506fd21d07e9246fc9a9f8d21b41a943346b5b9228e0db0d"),
    (&[0; 23], "6e1d6f3f23fe165f3bb252f567b1afba2bef3890a99a0b43146660600cae62f7cdd7d3b5450258448e608727b4c4d7a4dadab770cbdcb54295962eb055ee14b8"),
    (&[0; 24], "dcc6249d5b2df8b45e0737280a6e7fd1ac37fe673a4f5d250a708b06783e7e98e994aa26cb724ca05f9c55d88b4d843dd18da3d8269a7f01e8553a3aaf3a27a0"),
    (&[0; 25], "143af889b9d49f2555bd688dec85d7853e2dfdeab283382cfc2167e4d027df5275219c4ff34c283124f806078f1d23c6a926a27cdaf20fafdffa0d2139b8e72f"),
    (&[0; 26], "82f8c897ec0174251035a701c991043d6f8ae518380ad1a2de0efe71b655e4b2041509a83dc59ce372de9718c7f25f292d8ab20e3a64fc6e4873f522af0a1b71"),
    (&[0; 27], "5be69300f38ae2440e8c12f30c954508852530220f24c30113411176b2d41bdb917a457cbc1f3e0968fbbf4c2dbe5632e978edb8c4d20d7d595949f91c876c8d"),
    (&[0; 28], "66cd656bf2720c22ac408dfc7d2f9d2dcdcc9595d86ac497596ad66e804f51574252e8e287e1b0be9a1207db2b19c20b0a88c89c814206d2e8433888e38d27ab"),
    (&[0; 29], "d893e1718dadd4eab0aee5eb72603894fa99c09dda6b6695ea427e46d993412c38944823dce83e578dab3025a78b2937754e055c2a9987aa9b43a0637304d6d8"),
    (&[0; 30], "ec43e96b6786477d5df865962a76cf65b116c2bd1c1d35beb7c4c0ff0a95487666deadfcd63a4cd8ccc39cc4c9508957abee8e52276be1751cde29e9b2ea0b64"),
    (&[0; 31], "ca4febace67c258387986964061d98fc70fea88236fa8aa45462d3dd62a8668e43a1afea9fcfea4cd3a6d35acd81d25b185904fd4504bba398d63dc1c3e903d4"),
    (&[0; 32], "0f6f7226432c21d4dfa2a1538a1fdc72ee1faf405a60e5f408b344a2f5aab2ddff0f9c172b6f7e2259b7929bce06388ecf84a51605bc48cd0b3c51d0eb12e3fa"),
    (&[0; 33], "586cacb266c3ee51c134db0c4feac265ad5d79ce788a255d72df0cd03cc0275914672bd3dbfec8f1ae707de051658690d0cd8dd374aa04aa98965182c84636c0"),
    (&[0; 34], "f61e4cdc247a4e9dd7c5f047ded4708ee81fd71102258a90c7b81cbd04e7152a659b58944dedb66a1fd460c557258d7de6e3a23b259b72ec3c3a02820170f7d2"),
    (&[0; 35], "226a028ae0e665ee6505333de6829a1b5262d4a4ec1ff74107148228747c89962f3822c3767ef33e10f8af7e40c28ba8c7f7d442db4497a4f031333ab1d65c87"),
    (&[0; 36], "6cf200af0ecc4aa1c5c730f892de3e079d08860052ec8040127ccf62e9959bfbf68750cf3be283af7eb14f7021fcdcf49364bde16d154633547a4211f3b44c8d"),
    (&[0; 37], "e108e4255ebdf142f6014b88f49b58d5c3e3a04616b6092e4943190de2be711795e27e9e8e43fbde3f09d2c1ad52c6bff4e5a1a713bb3ede9864f935a3d12dfd"),
    (&[0; 38], "846cba8109d7a8341f7d203b0debde7ad2b3d668a30fd08d0e7422c0e2c99927bac188164f29bcd03fa499dbe53345a914833d5d6bc30aeb2f9567fce5d1ee0c"),
    (&[0; 39], "4e62f5f5437d3cafbef98d26ea8162ae0be58a6fb48920724fc5c6bc2e7baed1145687cdd60326c44bddf1fd20cd724fc6525a7b9c72e26b01a73f52ce0b5ab4"),
    (&[0; 40], "d1309cd8b0b8a52160fd35f814b767f7083abf5925afd93efc0e0c828f67a8637525e59475691fade8acdbe5fb30c438f82f1cb7d891a22c4f7e2078138662e4"),
    (&[0; 41], "a60a53056bc46b2a24499869f1530807d53b85d921f29b3d5cebd9c20bf0b091e9e6f1c29bad2dc5a426aa648f9fd0800cfc296a6066ae30423d392849b574c6"),
    (&[0; 42], "bfd76a8d8d29c185f39a9db9bbe7537674a009ee2323f3d96092eca1c54eba459c7461cf48c5c4395869e92c096327f7a244f3fd8ec0e5914f832e5c7d302abe"),
    (&[0; 43], "55e95a78a0178a4c016270efa585b6f6d1163fb5b411d49d56004b0602b7bb49c7e488e2b798484eb7a88bef8efa5a8124458bdd96f3b023882f901476f1fc9e"),
    (&[0; 44], "2cb8ebcc6f29a38c7ea298327da9f09f749a7dcbb0b691c2c59ba33fc6b0baece01c74f8a182be7ec04b48d88ccb241cd343a66306ff5c213b674967dafb8b09"),
    (&[0; 45], "df245f9f9d0f14ea6f03a4729a577c7d44a555404f12b65635b6eea8f4d09746c7c6f09de4d0dd85b77f796db125c3b85a027001bece5d3a5781e77543d84f52"),
    (&[0; 46], "706579773024cfae517dd1442ff5c61176250435bd7f5dbc1b35fa6e938093bcb1c808532fbe199e6acde729d0838760fafe53515afdd9623e4fdd98e0a30ca7"),
    (&[0; 47], "a93967fcf63e6914d000528edeb8922c7997c5576e912c7ae9a6aa260dc449ca1f867af3f2b9ea2fcb7a675648690e6c0f472b1ae04be4c42674bc06abfdacfd"),
    (&[0; 48], "0c113bdde1174e5191326ff26aeaa7f305b5a5a13c61b85494d4a928b092a9a148ad43037a4e7aff1da8aad8ca02f8cb575fa4626d09a673f61aa4a16ab6f209"),
    (&[0; 49], "1f319bd415c075daf111dbfa6e9715f4a25796cf9009cbcf576036ce9e1b7ef5f2fe9313d2efdd7d895bc6ab8810d0cb868284c5b8d570ccf1b6735f4fc7085a"),
    (&[0; 50], "e6dae2b61814d504c0d41bee8fb8e76fce79ac1c8aadd575e4e4c25f9f364d5d7c9e189e508cd40b08cffa8879b9a1ca7bff91e259f3cb897f885de445a493fa"),
    (&[0; 51], "354b3f099a2bc36e78d17c5b78bee5f0d0fe93d12811d4e341af0fabdc9f9f6418208ab47fca7e028bb77e45874ec504accca842d43446056c187b175951c900"),
    (&[0; 52], "945fd7147b27d1d15c76a12c601cfab807921cd0f3a14364392babb63fc147c3ac798b6857fa294afbd388a9643556cc23b9b633a2721ab0d02303d7a3ab5bff"),
    (&[0; 53], "bd758522808ea088e72ffd596cde4d4d138fc96a1bd4939c10a66447dbd29792131c8ae3d4f55c0e4f80aa6771005d733a55ee1ff3d18b8a1a615cbf9fb1880d"),
    (&[0; 54], "5ed9d9e78521eb86980b178dcd95eff423d78d1ada622b701c424444de0489aab3513e802ad81fee42149d719b9623657d14200a280c3b0c15be021691eb1106"),
    (&[0; 55], "bfd9018be0330275c1cde22bb73de71e991dfcd842910a6c6386a55722b65a290e69abd3f2597f53ab2e959e9787812cf5921e60a22343215cb1328b45e9851a"),
    (&[0; 56], "b3269e6d2752d21ffeed4e959143a2238192b00fdbaedcbcb73933f12c5aab34599f06f53e1831eef0a19c3b06715a5d6837876c4a400c1ad6dbfdd5e6280cc8"),
    (&[0; 57], "51e5b1530247ae4ee738555b360bb1d57f31eba57c7597aa4a2594f35647c126c88d4fb59e617e3237bb43db2c9b1922c7bb97d2dbba04eeec36cdc9ac42d118"),
    (&[0; 58], "fe57e03c6496c048315023c7c4afcfd0ef4926912bb27405eb2012eefc595ffeff8eeadfe15c66d4b4535e4c23b0ffcc43f49f6ce594ce4e7063df16d30704a0"),
    (&[0; 59], "a3993637715644237e6b365c27222b0d3dd1302c4210812014a7c0673834409b34b4f2a580006e1885ee4801bfa2908963a7dd6cebac789d73e7e5d916398d73"),
    (&[0; 60], "10503ef4990fa722412411712a3ad8ec55863ea83dce1046dc3c5512b9af7a1b0d4b41dabb759c351897bccd550fd6f70d792a52d0d6bac5f2f88b07c5f03e10"),
    (&[0; 61], "ff1c5ff9ffaf056d68a37902d1e70a1f97313338439ac58290d72607652880f4f178099293216338d3fbb4e4ba18bb92c26a073a4acd853ff3f0f5617cfc0438"),
    (&[0; 62], "a91c3dbdeaac61485701e8c8c45e9ef0628c8001fb6e7e031e3e0163705b3f7bc20d6d734c9048adf0bea438a18864f6b3e46b27bc3b6d74690411f159ae71a3"),
    (&[0; 63], "ea932c798cd49e609363ce478b06ee469b7ca11b72b586128a6154212bf1c537719ad95d2eb09310a8bfc2981807fbee4349f7cb6a88bd9bdf22b2f7f80c7847"),
    (&[0; 64], "a8620b2ebeca41fbc773bb837b5e724d6eb2de570d99858df0d7d97067fb8103b21757873b735097b35d3bea8fd1c359a9e8a63c1540c76c9784cf8d975e995c"),
    (&[0; 65], "a9cdba36670d15adea023e47166cfe67fdc1f94e96f99d5ddf35abeb29987ac77c70808f411a4c03f634f088d5eb858a9aae18af407007de69c3d6735e433902"),
    (&[0; 66], "5207bc429d4aca7703bc8a5138f635312782160471ec6275509e5f6f8b980e1f2f14a92eabc560f432dc7999148b79e12e001eec6d45f80a419eb20b79889f0a"),
    (&[0; 67], "ba93682513595684e6dbdb6db27e22e5de1e022d350a28e6cbe6ab9962c5cf3b98b189eabd64614df9fcfe59e7f853b6bced94754cb74793cf528a28bde3eea9"),
    (&[0; 68], "2d95d73a4b72ce24006bff27e8918445199c0c035a092b9cbec4277a13a900a7fb56388f7acf405fe9247430e1224b0f56eeeb42c212dca9099fe3d77a8e9613"),
    (&[0; 69], "e8ec973b9fbb12b4eba1131e58524550fbcbc426d15572cdac4fc180ce8eb747a182c45ce794b4af9dd605e750ed7a51c3fea160fc0ca82fc0fe292130a318bb"),
    (&[0; 70], "2647fe091c82f22ddd1137eed04a29b2c28a466e34cd508282b45857d07339d65143239e5931cbae221cd8616be65d960e1ca3aa26cf5141ab360475034754d0"),
    (&[0; 71], "cd6559fb64f7e8e4facf51d6b402804d2006b04221e4821573ed9a368a7654ad1329d40df833c486e516d402f1bbfd8a14bdc3a1588d4d68c8341cb32e5091c3"),
    (&[0; 72], "bcf38e5b375422155b4d8eb150682a14778b0695d709cec479d013a772497bc8d7050ef2a23d69609d609b15e5001f275c4619270ffbd6e8c06a7a5bf72334b3"),
    (&[0; 73], "2937b9a07a95515ba302f6b5b4fb80c6e4771d72ce148e0c55268ee198f25263a4a191e3f8d96946ec5c8ffe5bd18d01f03ef5081a3471101e59b20bf2bc9f92"),
    (&[0; 74], "84ad25308c082e8aed5b8e7e2d65468b165969afa5034b92ecf76d9a2d02d4532219e956bc5845c5efbd5a22d68db3f1ce023d96242bfe60a4d2dd272db8fbf5"),
    (&[0; 75], "170ff6f5483c1d812722fb3b6d31bd791f1c7d965fe98078cacb7c178a34667795af55f0db6aac417abf4e3fa17e9754cdbfd48730d7e37a23127fce019cb713"),
    (&[0; 76], "a7548e15733acfa210c013e2ca7351e2746c18c68b77576d5171236c70873717682235d72fea2f30912f48aaed38e396e8c2ee9a2aa2befc7cce1a43d9202455"),
    (&[0; 77], "b00d9d7501a7abb37811239d9035b1cedc86270ebf2750d51f65014f3516bb96860a2472e906f278cd2f16d4e0fd3cb3e51816a7b87d2d2266d8cc8b747743dc"),
    (&[0; 78], "22d4ddb48d5da1ed7d96966d15baf4cf3d6914edbbe05a8aeda4d72fbc0ecf2255b4e5dfcfb8fa1e1c7039d9628b98d019c7193e365451b82072fa27ab116f96"),
    (&[0; 79], "e15a478e5f72447b6d3254ce055fae5b7045e429f4e66728d73667b1077c75955b569f6391a703f515e49248b58bcba13bbf9bc6dd119ef26d42f2af154c59db"),
    (&[0; 80], "558af02442b24184ca8dca7dbaf585f11fab710ff3a731fae41447a0bac9697f01aad930e859483565be3ec03ee0e54f459ff7652aa514a82c5d28944318d87d"),
    (&[0; 81], "607e314c0e8023873a0b1b30935ee5b9bfe83b2bcbdddd224de940352898b423e7a65115578fc48e73a53e1cb1477e5d19b0586027f3f82a93b5b07ff65ce7af"),
    (&[0; 82], "df6e5e15a33f04c33dc3331bed0cfaaf7fb14caf50638d1691edc8e5db8f2daedf30e80d0d1a3fb1c33ac2887bf139f874e14aec7c7998227bfce9ce384892fa"),
    (&[0; 83], "4eb8f818de64b023ee103298555d85c4b149776dc20534c1431bdb8631c97ef7af792b4fe150ab0a88debb9601f8bf8f4aa99d3dd30e69dd561165f43b951173"),
    (&[0; 84], "f736890f224bf004bfefcad1518169dd2ed32f4b5251aa3a7e20b446942cbfb2244f498baa9567b820e1d984b71c1ef3e5a5e7f522fbbc302778a45304cde4a5"),
    (&[0; 85], "4f08d24b6f105f4e36c17cf97dcc87c74baec3a531208208df0e70b645ac6cb87a773b2bd61f9d9a2ff9d5374f3742ebb00c7cc4f7cb864a2b8c47b35162c7d5"),
    (&[0; 86], "5e8b74a78f8c3b641a8f4184c3d50e1220fee02351aee7c92bbf2245423967cb1eb366c252b1de27e80d8ce14aababd7194ca52482e96f8d4129a388b604529f"),
    (&[0; 87], "15575db9884dde3a97214fc003873418163bb949c8d22eaaa4b183fed97cfb4b305569cd469bc3e436170229a708d7f0805eaabf547bd637ed432c384d9c4e22"),
    (&[0; 88], "d56be1730d536a94d896f87e98ab97387a349ecc63ed8962b57299c9d34f0bdc78517e99abef567a375e408357246723792d7b7ffd31aca63b70d089df44cc11"),
    (&[0; 89], "c54acf9dc761aebf9e7445ef6c70d8a8670eb34ff813a02470bda99f44d68e274648e4ad8682a3fadad28398ae6ba564fc5e04cb447b5e90dec35f659c4ac6c7"),
    (&[0; 90], "c5fdd17e27a0a230d5181a51aae6548851f8fb76054d74c11f30fe31ebea0122696ce667d46b6af5b60147c74fb6fcb7892de1bdd2a0a6cbb411ed2e110ea009"),
    (&[0; 91], "a4d3d296aebd475a1517eee30bfe32fc4ed6bd12d1a547b5b540fab829dbc5d81a7c913e9b17edd739825514784aa724707bb114220b457991455bc22315acec"),
    (&[0; 92], "96461529732f1bb902c725baeb207f6dfaed6073919a209be72f1490a6cec15910fe7b5b8621985ada770371ec7ca73684a6c087cfdfd4059df8129e481078b0"),
    (&[0; 93], "70b00d83417590e8dd9af64c6bd74e499f2860ce0e0b960fd83fdc0a456d4f58e3f68cba655b6045163f95e8cde905b25fcaf412432d57001646ab6595d52592"),
    (&[0; 94], "71be7d3ea78863e4682bad4c7a74acb713dc4d3effa3bb2d3b65ef934d069832d0ce4f34d11e667ee8c6a60da67b3f1e0b97cc0466adad45918ead71155d8866"),
    (&[0; 95], "afba50a6a4ecc1d1de295c9620d7bf51810f6b0a0db34697653c69084ba629d992f054e0040f70a1d10ac02d028f3d30252ca078047ef66d2f0d594ff22a63aa"),
    (&[0; 96], "4783d97ed1b7b139cca82e8d741a7d6e86095e99b2183cd5438656c404a307c21c2bf1b9ca70fcf67b26c72214c534921f5ff9215cf5f32138889730d8776bea"),
    (&[0; 97], "5b05f3f773c768f66b54634e6ae972b80e5be82e75d08127efce588e8abc1e5eebbdd7116a6149a147ca3f1b2236f783c222a5df45185b1f8fc98e4893098c39"),
    (&[0; 98], "b10a71290d8a481c0cb532e9253a4dedad0857794729959e284d4cc1aeb9b99785a7d3995715cb185ce72a97f4e6be0a3354fefe9ea1691102cca938c2427eaa"),
    (&[0; 99], "7235bc327c051cba3b85029da6fc665ce47ca8a937f69334c1f9a1a1c910213afc4795a1581e30440748051ce81faa13ff191413d4183933db325c3402a75aab"),
    (&[0; 100], "1c5ca839f350242bd82d7add22bc25dc06f5164bdf21a3562236d7556dd21f1fdaa35d365737ad222c7a3ce5360a66ec69269e5139e555a060404e5d0496fdfd"),
    (&[0; 101], "013c07cdb2f759abe75e280058d490767f1401e4c05d2c2d37dd1eb3ae841230eec9fc38b4b4ec1a410122591e38e1ca76b4a1b55b1bab3fbdac6d9f23575212"),
    (&[0; 102], "eed23d737a0d1eb9066c1761b34a5d746c0cc569fb9247850145de2eaa6a1d40ef384bb1d92e7c99adb6b498f6a9438312d68a3ea651eed3bd5f931e707ab3b4"),
    (&[0; 103], "ccece41a38583669b4dad38374be19da6648f3b6115ea0190bc0c17ff1e2d5ea000e9bdfec47a34279fb20797e7a5701355c713dde9df8d36be22f18a2b9f693"),
    (&[0; 104], "36958de9430e81580969e75f43de22ae9e9f403297a230d90c70d7b168df56322e2fb47a3e8f79a324b427f277324a677df33f85b1936bcfce764a343bdaf439"),
    (&[0; 105], "c037d846d1f8734afad2b5804f71e4821aad9be89bfc9fa42a6dc0d042a4c8602470b46e82e35663c36c99e3eb0b4a7ad54ddfce8f45d6495775cb5c2cae8f7d"),
    (&[0; 106], "97db2177334f812c767ac858a2734c0d540959f984af3f01183eedd117637a86c7ee61b4ba83fb808b11bcae8c5a690483675b05d4b38ddf251e43746519783f"),
    (&[0; 107], "2f2e475cd95aa2776f71b8330831daabf02af4f7edcd8697c22247a281e45e6acbe0873d172126aeb19baec854877ba6bbabd2a5101161dfa5b2f352767e1ca0"),
    (&[0; 108], "3a59c3c24d933e21f7d7e9eb868e0afb64f31cbf7f95d102fe4630ec023ac0bd9bdf0cb3dd41601cfe12c9d5b0f32f00675cbf1cc7ca28e82340506b5066995b"),
    (&[0; 109], "2d6bc8cd051e8e6f457724a760a04ef0e21122d54ada691e83ac5e0814f77beecbc9f658523d41a6423ebb43f5358d68c2a13fd0a57273dfced0e84e218cfc1c"),
    (&[0; 110], "fa2f6d251c32fdc318445ab33402d3cd0c85fc214192ce61730dbcb33349dac386876a31b962af2ce2bb2225289e317dc98617d4f5595881929f9a161d8d98ed"),
    (&[0; 111], "4e067d9a6ec29adca9abc601e8af1c9f53a9d0e1b667a0d164ff5eabb840079cf45b77962818367f79bb2f3a2f97cd57acfe665277f283efb92ee0219fe9d140"),
    (&[0; 112], "8794fe331fda841ef0abbc519c51583c041bf4dd2695a1ed0b584706765dcac034ad56e8c6fdb15580db3575b283da3bfef43013544961e390decbcc6ed5a485"),
    (&[0; 113], "b763866d72fd291afa551df8da0a138cbcfb6e7df1f2c9282a0276ed4ebd8f14430daa1bb67c58311b362094b02dea036423f0dd456e23ff0c8a462022480ca5"),
    (&[0; 114], "b0602a29951093a48147caee98b35fc8e6015e238fb581c64dd4b3008c168e333b37f1fdce21b26da776cd6dcef0ae2e56a006f2256264f9b052bc30dc8076cc"),
    (&[0; 115], "e44d6f918b6e7f5f6b2ad83a3efae94ce4bf4cf7fb72d70ac4d7790201363133bbdbf4ddf901165f5d1ddeebf52fc48cc62c3fb3a3fe175f72104b4361dafd95"),
    (&[0; 116], "cb2fd179ad16631bd112cde3233662667de80fc3f957477dc64746a577dea47ab650e518ef3c1a0133176f07b923e337fba91d1e1b85648b13bb09d4a1549849"),
    (&[0; 117], "bb3f55eb070283c1e918ac326e993121c1014f5073d73c38a45ebd5a42e3b422b2854ca620be41b5d2630b1dbd986bc6447f0d47ec8a2ccc40473618d6e90e5c"),
    (&[0; 118], "4f60b977b438ba52b8896e04bf5c2c0497d54562642469407b2f0e4ae3ce182ec814758e51a939a6304f3758855fe17e64f3871994e3d156db641ceafe46041c"),
    (&[0; 119], "be5c864dd66ff23ecea061002550c1ef1398a024ab9537137b448dbdd0e34ce8f88595aff41d6f773a61fe51f6c5c21e9c8f10eb2b417bf18cdbf99fc6f73a16"),
    (&[0; 120], "2bb0f77ffba8d279fe1dcb19c3e233382ec2c436c0127c4f0dd43999e2e6317366cf1e24762eae7b3fe422957bf74634a27153397e9aeb89fed2d8dc287d848b"),
    (&[0; 121], "c91ceb5b075354f097347980ff4f98dc1199a579e491ee822ceec0b4853f7fbbe20622efb8eae46dd8b2c696003975c2a99fdd19b317f60c5bf083fac1b1f55b"),
    (&[0; 122], "dadd9edf288d07d50e883e27cc3047152b2631f6f8b77df2028bad53930998e0c3a6649ef3961962e693e7d9bd051b917f713ee11e4bc4953169d415dd2aeaa5"),
    (&[0; 123], "440a11af976b7b7bfe4c7b38d0c5a370222b87850a05fffa0c150e322a057dc840407e306f7a307255891b8e603da4d8f39df10fdc58f0a58b605735a5fddafa"),
    (&[0; 124], "9e55e9f00bff081c709c612a1628f0f3975aa789b9e7cbe8cff158bb851aa3cc584ad8471375839679527891c21311f3fc5c4b838dde581252cd1a28b0140312"),
    (&[0; 125], "3f4573b283f7fd912c73d50dee42f54c069e14554212dc1bf29d26414c92025cd34c4d424fb9e0e0dd4c57d387d18d5507a12c7620efc5c32eb96edaddcf960b"),
    (&[0; 126], "cc0014ca391ea1ca7d4aad33f1c38d9ab086477fa8ac2919a310ba186e0522a015291562d4ad5bab3d017dda0d634f5321d265e3fe36246e16fefed65194d995"),
    (&[0; 127], "f1abca4aff9fe233bf5e2e47a00f984423c22ccb1c3c72bd462c370569d152e7f20d1e2eb34b6a89d573e28f0297f6c8d75532ab712083f3bd82cec8bdd10e24"),
    (&[0; 128], "3021fe035b86907b147d9a0f9dd67ea13561e439072672af02648e263a49e7ed3582a862e578964ae6f6107b9fe20bec8d4a4cc85491f8d152601df5a3c016e4"),
    (&[0; 129], "880ed64689859c279a1c87cf3c4533b7415ba3add5ed7c6ef64b125e0ac2dedaa303e4fde0802977ae9ea59da78c0aa1c09a4b5788d04830b82b888398eaa4b0"),
    (&[0; 130], "34afa089f867a485c37490b6847b118f825b289a9f45d461a6d475b373015dce832fa5c00834a12432aba2a56c3193d5ea1e4ee93dbf67e7b9765594530d7fca"),
    (&[0; 131], "1b35ea43ec8c2c52cb59678b8cbfa254d09f0cba1da522fc9b5d9c6c84c72cd5854dc695f7cf7fd353cef89ea470975589a3115836264832a7a84ebff96a2e31"),
    (&[0; 132], "f2d0fa4b2872526a4d863d3cb6845447712f7212330e10b365e69586f2225ae2ddcd823c99b8bbb4da36517e29e6284edced53fc1231e9431c14fb83abba92dd"),
    (&[0; 133], "7f70b015ec64e14de218b367339d7fd63cc8fc7e32222ef148ee06c88db65bb6514dc9df5a7a4848859eac69f1dc8b1035746a962ebb874cca697a0c66fb5cd1"),
    (&[0; 134], "22a5eb299c083624a9e74dec02512d6a9b9ff8d7e9984c0299edf5cce283f41608bf34ab511900cb6deb49af2a9118137f53c7a4c367a8f337f186134b40a582"),
    (&[0; 135], "b7b68bc1893f331d8121316c101bd377b1ba4a3d36a53329328755103020075b1beea984bf67c1b97fa5a342a4d0660e4669af6c4e06650fe1aa7e991c5b5723"),
    (&[0; 136], "fc446bc11783b4ba6adbd91a86457e8d537f05c945bbf3c240be902ce5871abfe08f7b916190b69556a876f4f4069d34c80cd5347b8c59b52899362d53be2fd0"),
    (&[0; 137], "a943c444a52c153c4734e371fae8234e6e975b3cdb72d85b72884d1dfc1058cdacd1ff382495f61afbb02fee5b30f92063185383bf032e8befafe7bea4d7002e"),
    (&[0; 138], "0af82b6c4d47c19c2575684e59b02f1f01f16a89b2dfcfda4194361566c8d23011ee39f64747c1f38efd6a9f7f706c6396f59ca9d71c647c8f18169155bb6363"),
    (&[0; 139], "130adb310e3f6c5d5891d80021f883c61e225981bafa871097a30f0adecdb9a375dfcc09c33b4bb9cb75f2b7ed91cc0caee224c6ac36c6f42a71372fe0e40927"),
    (&[0; 140], "986f654bf2e23cd9dceb4267645e4427be9549f8c8f74b9596896fb30ed3d9be541338a9a5420535efd77b5a95c0a8104e9d339be3ddd59d1634205ba4bb9cec"),
    (&[0; 141], "4732aa6a56162bb63c76508df77748a5dd6641f92e41251fa0539bafd74ac191897846fa26d233e9cf2086dc06a58c3d927836fa0c2da4e49c3a6d7e462c7f92"),
    (&[0; 142], "ae0a4e9358f2ffb6ca50106383450b9cd36a4ddf96303d7f66d38e5ae9f6d66837d9e70ac099a26615ec00240dfefd0c621545af8250b788296dff50a61d9c5d"),
    (&[0; 143], "cc51e78674e1842c819b49391526b50ce45d16e5966b0402a63e9b28bf479896c10cd4ec07dd22f367a15ab39ef11efab43320a58552736122aa4cd7513cb890"),
];

#[cfg(test)]
impl crate::hash::Test for Keccak512 {}
#[cfg(test)]
impl_test!(Keccak512, default, DEFAULT_TEST_CASES, Keccak512::default());
