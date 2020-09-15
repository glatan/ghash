use super::{Blake, Hash};

pub struct Blake64(Blake<u64>);

impl Blake64 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new([
            0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
        ], salt))
    }
}

impl Default for Blake64 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new([
            0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
        ], [0; 4]))
    }
}

impl Hash for Blake64 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x01);
        self.0.compress(14);
        self.0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
#[rustfmt::skip]
const DEFAULT_TEST_CASES: [(&[u8], &str); 256] = [
    (&[0; 0], "223d88a8c8308c15d479d1668ba97b1b2737aad82debd7d05d32f77a13f820651c36fc9eb18e2101b8e992717e671400be6a7f158cdd64afed6f81e62bf15c37"),
    (&[0; 1], "765f7084548226c3e6f4779b954661df49a272e2ba16635f17a3093756aa93642a92e5bddb21a3218f72b7fd44e9fa19f86a86334ebeda0f4d4204bf3b6bed68"),
    (&[0; 2], "4c33bde178bea1e4015fa515a661a666dc66a06ca81c3e6ff5834cf6100bba9f1b847c968344a777af1a31b3b796dbbe38865550b18e77878ebd50168e20ae97"),
    (&[0; 3], "1691b359e00bca53f4401088c8054cd95b2b4ebf99fd18e019dafc317e583382b33445374cd846b970c83c70a46e2d089a9e93104cce78f21fa39fc3f77e6139"),
    (&[0; 4], "09f1eacf4b83289b43e1e736a68e061f8e7f2a42e7aca32602370bb39eb5a65e9cd3f166f3f8bf1e09066992d860fe6852bd0a5af4a821d9330e843793f04ad8"),
    (&[0; 5], "09c850bb88cfdffca22a66f07674a94634f6f8a4d449aa70b311537eea3928770d60cd70a6d2643d1aba4ff5fd8c95e89fc104bc36b5a0d6ac59e984e3ba0dc4"),
    (&[0; 6], "10b1ecbf34fc37c658f59a4c8d8aa987efaadf1e27b28e47ac6d42f7ad4428a586874b13c959f5aa1837d3aa088af52fc10eb4151341a607c5964c231fdf2877"),
    (&[0; 7], "e3afa604be30bdfe1f2a906fa9dd90a86106af9ee277ac840e2185c9dd2f3daaa1e37cde4f3e9382461b4ab0eb68ce0c12bf2bb28e3cf8cf866cd10e10ee45ba"),
    (&[0; 8], "4dae6b157294e9cd450172fc6daa4eaad2f71a16f2ed39120c019929174e205a8d3a6d94d3ca88a372710523bc530a8530936dde580ba3a1461dc4f0f8809945"),
    (&[0; 9], "6c4e46b763501aa796054aeaf3c95d7e17560a70a751dcc4ecebcb7649bd68cfcdfad1ec710ab7857cac446feab387199427c48cc212b1a9d311d461bb8fd2a9"),
    (&[0; 10], "96b6fc5ec3dfb89cf5c88b1cd410aad257b9290603cf320a0d7b18e5f6e27a9d6d0d4d47c37a14eb10bc38786c9844f2ae8b720a256edf9b6501f2b1c6190ef3"),
    (&[0; 11], "f152db4371cb34d663a0320273b8f479251833b65148a286d828264b9f52be6ee9d7bbe33e672d49cdee18b17e1e95749a0def689310a752bb66690fba06de49"),
    (&[0; 12], "1deecea9ccddaf0d183ca868d94c06df98790ac044ad110bb2eb6df4d2cb8e0c508b7a3c9f625884e6164b3add3d3273c9e547089d64d1e0f18fbda19638172b"),
    (&[0; 13], "d888dafa98ca3393b48ef60bdb7d13e1d5459bd00f4b5cb472c371f36b4bf6e4af4514ccdce74bf4aa8cba1e594d8e3be366925bce630d1f587a4986ab6415e6"),
    (&[0; 14], "c624a07bf92a0dd67e3aa4b0cdf3c297a9c5ec2119060b3919c49e6b2bc6f819f7aef96610450cf9ee9c3e795feb60c9d480e95dd6ad47213ccc96c0bfedefbb"),
    (&[0; 15], "fb41dff370d44d004c2d32750316c77fd480b11ec686e5796f97709b75c758b38faa2b961f978028ebf597f5f9b2b5039c7dc13888bc56390c2b96f6918965bd"),
    (&[0; 16], "b48b29d48138e37f1675520135ecf6d5a678d05d23d3ad59a32a69617c433aa145bff6701a579eb10b83555c7acf45e0bcb2dccc29d8c9d548ab3f7a2523754e"),
    (&[0; 17], "bbbb5379444a22105b6943b39e2cbdd7277cf501fc38a04da0cb2a8e4f83afcacb78d16e6cbf66a32f79c01b5f04b83a925f85491ab083c21cf4751f0430d442"),
    (&[0; 18], "5fef942f3056f142da4d1de22cb2dab21d0e54f3888838aa65760b95f03f2efda9ebaf0ac9571741f03f6a0f20c8fbefacd70831885f8a86e10fadbfc6e791da"),
    (&[0; 19], "bc4a451cc845540acd40d08924f6df1b0c4a76aa44f86778e690badb5d050cc863239275fda400238e854b8cbf2d3724f8aa6d26e282410bd85e4fbc8295900a"),
    (&[0; 20], "1c225aaf15f8ab7b995b4cd7bc212bae5824c521c9cf1c93181910d721dc43428ff2c032216e5916d10750a66d49b54772ded9b682c5359c455563c157b7a0f0"),
    (&[0; 21], "1a1a225154f29e3fb9c6d3f38dacbd96312d48ba6c508effa2d6718eed29fec7fa7d7b95b9311de9d5467ff0e2f3a565f677d2fa781e813a981882299e4feaa9"),
    (&[0; 22], "e26751c19308e75b5a72c133585fcfc2b387bad14497258a675f953441f54a99a6e8fdb836b273633f242f3edb22518525b1a18e4d985e83bb1fbf59ea4997e1"),
    (&[0; 23], "e80b1cd89857184d1d9c244eddbf5d59d70f717526c49bf033be97f2a9dc92390f42fd8029b290d700b958880cc1955ca9ddc3f21d8f456d69f32affdcc3bdc2"),
    (&[0; 24], "9f7923af9e397a7aacf1147153b0ac287962d128223e5235aaed6360df6627467ce890fcb9af5544c20d8a849649d6dca4318732e3b9a72e406a15b8293e5d97"),
    (&[0; 25], "67b0fe6ab0686f8b476873138b088bc265e9ecfc3cf06c4483be7c90e9e8b3ef4f620dedb652ef4337dc444d5acc9917b0723982ec6ee2cee9949196a9070a00"),
    (&[0; 26], "a3ffe91c0bca7e91ed52580125b55b3d29e7e9dce5307ac3d7f6c50163c491c306f8ebbd3a137bfbd125168bd860739dff16955b23ccc60ba097f51df04373d2"),
    (&[0; 27], "273d9845b3346e53bc246428388bda6ad3905caa7810d7fe536d50ec3b05b64812e8501b363e0c6a01cd72d2a5e9a9ee40846e02397882f22999e8bc979ead2e"),
    (&[0; 28], "a24a01dd49e4e3fcea9acf74ad86988e4a20eaf0c3d13799af9fbca83b0afa2d053a6b11d6e46603a5246cb21b1f4ce1cdd8862b582d5a3ce0c420803df10c4f"),
    (&[0; 29], "c847c3e5a24c43aa2cd84654b05e7b943dace1620ac9734e99ee98f59f0ae25454f64ec0f73561ce92e05f235ae91b0a258f9eddc93436e99e893ac97d143f95"),
    (&[0; 30], "3eb3e62652ae4d160f13b923dbb18950c3ce9b4f81e5a32b5de6d441819a964998d9a0090bfbc79d9b91457ccfb8e6b55d80f08cc8ee6a6a689c44fceb3a93cf"),
    (&[0; 31], "74b4031a3331fe1d0813bac10725453809b53690e7b6e9c433e42cd8f0b66005a1d83e5d64e14497762c7c7dbd6a2543459b64818687ac754431ed49478fff23"),
    (&[0; 32], "5b9a9b7c5cb7733b3d40e388e467998c7c2e8ba3c80142a00fd5e3abd4f740190a11194b65266601db4e0d9497d27f790618bf35848d2c4af8f2d248dd72cc4c"),
    (&[0; 33], "db10999205ec44e6160c6d2fc7ee049b9914c74f521333a3af56cd911c6173f45d53e0866611aecfe95ef30d90624eb623abfc54a90567e3b73aa5c52cbf95a7"),
    (&[0; 34], "8d7162f01da6362e7534c28cf3ace6e76d3f82ca142693f91edc4f1d2514effe5b2e6e8c037ebb52154721a78e366fd1a58b9f536890a020f86806fcb15f2748"),
    (&[0; 35], "8492d407ab96c1b3a4f37d3fa8a4b014d567936a649e5f1ba4f82946e35302f49bb830f81cd74e341e43cbe0ddf58056b7d562f2365f295d9093255a9ba34244"),
    (&[0; 36], "ec8081ce975fdbd93e3d8079572985a4322526036ee41eb8e684fb9d921911a22b929277704437e53629cd3537aaef57952113b7c2a7ab4e2de25e5c9f2fb718"),
    (&[0; 37], "b53588efcae145ed500432d4ecd433f039ded636fbb330cfc80a6d303eba7d9e7be2529fe44d6f59c4a5856a74fd063bc034b08c4bcfa80a4053eba75f780ab2"),
    (&[0; 38], "21efaa0b88b9a65827d2da8da21122aa0a39e6bfa6226e63ae0e8b0e5ef1dcc0fa3c106a3a041434668871c620ea581c07a8b1c6948473c64caf621300cef902"),
    (&[0; 39], "50a323a34965d3e37af59bd7447418c51f91e18b307ebe25b3d1a918d871a91619329c5d8a1d0c6ea7610307f22d5fab05c5af473b890753d571e5aa8570a544"),
    (&[0; 40], "46404780095e41ed84db49b681acafddc8db4038deb43f570e98556924ae1aec5d99ad4667064482798662cdc27511e0473f8c67f93a57403d63e1f54a0a52f9"),
    (&[0; 41], "d53c93d3e1cfa489afeb19ad35fdb0a1376d43e5ba553f5669d04205e83cfd3c0ef3bbcbe463155bd4939089fe336dde3bf0512354edf57c540abfd4af237a22"),
    (&[0; 42], "9d1b6f969a5f831f44da51d68a0fbe34236431d5201df48e2c28891320a6d3fc72ebe3f477ca56fe275e5dc4a7e479427458094c6245dafa553119f95d43de69"),
    (&[0; 43], "3acb67f355052f78520408096477e34618c6da93a06328aaa937aa71b0409e498e23a7bbd1caf143fb403015ee917bf389b9431382afbf1b6ee31725da2db50a"),
    (&[0; 44], "0b90318e53f9d9d021721e1f37fd7b09301ef126615ee80b144e2329f41b59558bf40577a2e395cccb8e5b096322eafdb236e9e8494141b4e65c42214703f46b"),
    (&[0; 45], "33a977f162cf5f76b3fdde26214d2db592472a1b846ba6e9f882ddc1723c1b060dae2794519cccf259c1483b4759e02968f231ab3b6bd19297e5bf917ed0fb89"),
    (&[0; 46], "8f301a367cb137d3ed7e07a6bb72ab704ceca9957a8921231922ae3d82c12cbc77fc09dbc611d0cc5ffad1fe84936d0a1b89573f8036996b4c297be4e394bf40"),
    (&[0; 47], "2a116eea4f0a596a32c92b997ce000eece3cfb39851b709a8e674c5af68af528b6e7d8842441e4d0973c81b9071e8901ddc8c2769a51e4b53d1754ae3255822a"),
    (&[0; 48], "c61ea9db00857bbe90dc5e410506f89c609e10a23cddd28c766c8442f31ff0240531842c86cc8eeeae78d72dde9c212da02033a15577d846cdbeb0fc40d4bf9f"),
    (&[0; 49], "1006031e018b7108023a2afdf659bc835955e67105a7282cec6a6e618672956a6d434609ae5706818c29bde5d8b1aded4fb7c34c17742755864ab5810e363db1"),
    (&[0; 50], "997a01aa85952bc22ff8b5c038e71bdcae201410890d1d980e35080542ea6b9197d9c30425e9395e95c7cc28cae77be23265f469603f2eb9555ceac503bd5445"),
    (&[0; 51], "c5bb9b73826d8e9b437e9bde340f9127875eae19c30f0226075be239331fbf57c07492755d28971d2bd6bfe1a7959fa2a4f945b55f2118fa19a4d742403fb151"),
    (&[0; 52], "f6e08ed9cda0c9f32dd5bac8d9965f59532f6d57ad1a0920066147c0d2fa79567ab67455d7763d14327ee27e059d843c895443b60fb90ca5e95d680cb5ab6c73"),
    (&[0; 53], "bda4d9b363e417fa0b093c711883cc7e54635647ea5c966b2721c46c415f89cb53817128bb27209f336c7e30db42500adde1b6ceea6e84cc2fe89d35fa24c7e8"),
    (&[0; 54], "3395216a8d4e36a09e7b74f21b06f1a9b607252bcb20a7017e673402d063e209f205d6bf5552273c09e46fdcef9b8e3508c542927736a5c0a8a037b1ea693b9d"),
    (&[0; 55], "a0f9c1c38ae0f6c871a9fd8edc26c3964801583eba184a0cf58ba4a1458200cb2cbdc0f8598a3458b1339cf46248aee18690dad2d2e8d9a512075a9887a7dfbc"),
    (&[0; 56], "94bb039aa86c33f20c8bf3834ef00e297f9790007267d4809d94ecb54aed11b30daae762bb443615504f3d3c67daf67791edb6aa2d886f01b4078ce3e102ba7b"),
    (&[0; 57], "0170413e538cb1db01020bca2c8ebc23152064b068dc2efc9fd846f74a08ef2eae51833160f0f1982c5f1e97c9e5779d0e4399fdc712aad46fa17c9dac98e59d"),
    (&[0; 58], "641edd52a437e49c73cb7c57f44f7a5c11a179664478f2cb84cc7a4a059f5e36a6ce3ca471eb3349bffbdaceb98b97d0bac89c6479f441486604dccc03fea75e"),
    (&[0; 59], "bd4370111f01e283d5564a9e5ba592e33e985256def6d7b4c65d4c37235753ebdac39884e309f4e8483402e9a7256b778b992f55c6dafb235d4dfe9fb71558cf"),
    (&[0; 60], "e84dd4e0ee02499f2bd65263ccf720093f5e1a4771b21114204cd856455d63d97c5b1d662799e1121ff6b9c00a45966ee965205eff0d76eab6acd8d77e188edb"),
    (&[0; 61], "cc40e1b938261fd636f0cc1b889f14ba2752b9d26cb0e0f0fdd31a87a9c7eeaad44216831246b3ed01146c134e5019024307b150fe224461f0866ec5844e428d"),
    (&[0; 62], "a1eec2f798b5239a67ca567487321328640b4ac0bf0ebe1774b744f3ea31c5894118f333c8bfb605f6de679113f3b4a33905d0e5838e81aa20eaec1c807aec0c"),
    (&[0; 63], "49167f175174f6a70ffbb8347e34c5f820c9d726f93dfd3ba8c69dfab4a113a1e6e80972e6c1e2aa5c304cd43d8f97d043e4228531fa7c188963f3149cd3365a"),
    (&[0; 64], "a751f7f505dfad68df409a846f7f40eda7485dbcd0e1d0ba32750c61a3cad5f4a4cf8e81f9c9ff0333c080c1eea1ec28ec4e4fcb483c02c442a00a2c1fd5d658"),
    (&[0; 65], "9a619c5e8bc5b9b7190cdb9650c29866959b97ae6a5330b9a9dd61f8636c559ab40105c6442cf1aee32cd375d66f34b04d4dde1781d69daf6cc9d7bebf9ab079"),
    (&[0; 66], "9f510b87ac4c07b65b0846055c80f41625d739009e2b05fb8eb967f70930a424f2cc1fcb0de63c9b528f633a4eea694754d110c4bf4836c43f9c77eb5f97f371"),
    (&[0; 67], "9fe66572d6e497d1cf55b554ce9443a4bf250b8b15eb4bc402696774b449de155cf420bbda8cb31350ab3d01301aa70a3582d27bf09759170770f98e49f038d3"),
    (&[0; 68], "51e6cb4aa0805434319a249eaea9999613a5f7c88a046a47947292c88324496e402b1d01d697dce60c9b927de65b3fb05bf8a8248870585610dbcd922e6c0523"),
    (&[0; 69], "57a64a3ce207e7c090dd30e1b82bcdf734b670e1b86d8120fb2beb4ac90c2ab4794fe4d5d8d8d07d622dfac95bc4ddb2c7b31f007f426012131b18ac41b92fd6"),
    (&[0; 70], "6f149905d42a31567bfb90058c306ee5cc2c62b6c6af00daed74e92778d7005d22f54eba4e04edc5766de142d48dcfe1a34190b63e96b591bead005df90e82dc"),
    (&[0; 71], "7eefc26116e829e35f4a149f47f2623bf130491f5d370e987d18deae85605a16e66a700a03712bf677a2ccf176fc7c6ccc768b8f9f04069ab425c7d5942eabaf"),
    (&[0; 72], "7ef3d20acdc85ee52cb22161b3766a6e350ecea9e292fb656307879b14b2446d26d07db3e2c27afdb579239a8d1532b8076aa765f66581c30fb32a23042008cc"),
    (&[0; 73], "dc34a281bb9e2cd7a766ac2ad10a05b94d528295a3f729496d9603353cbc6004a4f937ccb2cc4e98ee9dd40c28cafa9b4ea09241ed3081b0d02d4ad7ca610559"),
    (&[0; 74], "d45fad01efb0963a98d0151bfaeabd4f40cf51387219b9a330d4a96cf0b5863d3085a3f4700b5b1f87b800c277fd13e332093483b60dc78735c662e9ac647fa7"),
    (&[0; 75], "ec70a79f57c78569a12971b565d49245ec3e9af3fbe6ef2556a7a6921e081d47973333456a658d000800e487cbe2cfa6c4d993d94ac9c432031fcfaf528dcb35"),
    (&[0; 76], "5129d00ccf4dfb1f6ccde552c27d3947dacca49e2ccad75c09f492769074e5987db1a79f0de7006f459078db7c492c725c151574f958946848b8e96e2a1a9fdf"),
    (&[0; 77], "e81006b4a936f9ff17296a1524cbc62caa93e7da4745621f1871a0e9952b607fa03e6056ab44c226593f455c50c54a6a8387ede5b734b2c746ee7ee1bdb9e41e"),
    (&[0; 78], "a186ed7d29156ffd8111d31dd9007aa5e975f6a984ad95d0bc0375faa1c8edbc55c2aa35055b1eacc6ce491eb7b675990eb3fdb4db8683cf2133f4e7e5581499"),
    (&[0; 79], "059322706bb14472363ec16c18cace7ef84a73d34ddd0976f3fe027339b6a5a18c65fd26589f83cbfb30881674574e0e3d4923008daaa9c4f149246ad3a796ad"),
    (&[0; 80], "960fd15e086c9bd41b66d6a2453ddc478554bab411aa5dbe7620b2e7a5b65a523b6cf6b87c02a49bdb9bbe2b7040557fde3b7ce026c19d5a5de867f7d3ed449b"),
    (&[0; 81], "e70e6e151edd24ee9814e080c6c85b4958fd128f6c8125425799c01d13ae88788d124dbb0b46392079748407e86af959f89cfd962839b513ed7563723a32bde0"),
    (&[0; 82], "01ae389963d9007e06a4a9fbc0bebe6dd61a5d6de789f0a2ef10ffa9fa3f6fdc6ef78392934e68918630274abe88a426c378a76c6ff3cba68e06b7b007c7247d"),
    (&[0; 83], "fb574489a82d3727cc2e8c0cc291a23bb8f09de5835e81fd5744b2fefaee7da18a9103f9b8d459f05b84ea4459a9fe0af8f0914d81413ad200445ca2853c42d7"),
    (&[0; 84], "d9070a1a54aca5db807e5ef364b9bf581b8a8524e96dde644d97564ad930ce8b4245b21f51a2988188ec129dbe01a6b6c4e3edc9465adc53a41c17098d0b9b57"),
    (&[0; 85], "80be210c747911ceb929c036a77a42bad0c69883adcb64a0fef2ff2dd76fe21f1b7275cc10d95337c0eba456cffdb4c632410b2396b2bc72c4aa749b5bc64007"),
    (&[0; 86], "91b9e920b0457a52d7bc035fd4afcddfc102b419600a0a8765464c6b0cc1b8f97717866d288200fab59de785383ceb5f218ae0c380834b199da7be96004fa333"),
    (&[0; 87], "fcd01391b0b1823106e39bd6eecc840767f3a894deba8f5df0dc36800db0b532af31d4116e98681d83363428e0081a0bf654dc81b940267e74752cac1dc40a79"),
    (&[0; 88], "d369a727dabec0aeb763338ced777cca46524446e06eee708c1184e39189a9aaddcddc5198363f799ba36eccd56d924713a7687a21ec3844e93cee16def1859d"),
    (&[0; 89], "05fa7bafcd9cf16764dcb9042604ea06fa95e5feebbd7964abc850b679e928d74ece4e309aa05336ff5a2a044fb6c07f84a66bf310142aadd7015555f160b85f"),
    (&[0; 90], "8d369ba603113221d7084b18ba4e2543e729908514014df7ec20f2d39b6e44ff1807462aa15c616599996292e115ea51190d290a4a28c03395c74590656fc724"),
    (&[0; 91], "3ef2d575041f1941f58962e22bb14bf62c2708303fae1bc61c15d029cc969d1c09a5e9609fc7d27cf4f4396cfc004a41a7af532cdca9339f54aeed6237262f7e"),
    (&[0; 92], "cee96ff856d31dc2c660bc8e3f7b0f06febbdb11a22c773396f7efc29f1685d69203dce1e5d01fb78d2f56d7e3cc0cd97139d41ff0427bd78cdc76db78bbaf4c"),
    (&[0; 93], "3caf8ae1fb5d8dba14f8aa5cf21d03b31eff39c140680a21051c3f3ba20ea78afe06cdd1a0c545e9555ae53cc23fcb5bc44e39ba585073103bf104658486ac2b"),
    (&[0; 94], "2afe3303ae24964eceffc78acc201a18020ade5ecad39a95472c2e635fcdad187d05b81cb9c71475deea0e3ac47da761ff74050762b1c508672f1760fd9fde0c"),
    (&[0; 95], "eba036c3149ff23eae49175574a648d9cdab52fb292491091a684169b017248f956fea1f07a9b061a4f076842fce5f3d6cbde21e856448c8e16eede1bdebab11"),
    (&[0; 96], "f5177d36841e174397d4da5977e09bee68f53393e2b9dd2b2b3e3f96a57f08ea3f7d8a707b4b7572a3ec0443d6116f36e9db60f2d8f22af4198aad8cf2a856da"),
    (&[0; 97], "75a0b49c1458b316cad82c1ec0758690a86a0c73cf3a6d025d56ceffadb36ea566bdd5e8706a3cd4862b5e9478ba9317a1016300cc1983cab36b0382da861954"),
    (&[0; 98], "2ac7608f7f1da71cb7f9a69cd6217d5137ee76d2bc3abed7e1e255141f8a69c733a504b2c368d12f74a39f805d86846eacae9c2819f0e31736d2cef1d235391d"),
    (&[0; 99], "582dbbb794c5c8087db2e9924750922e398f1ae80f7cf10be9c936f60415ed5172f82811fc53e1766e46e0f90d54e55af56851de0bd20b88fc72e87b14508431"),
    (&[0; 100], "4f6d651056775fc20d54f174eff386111f727a0081247db22d8516003f19604b47f7548b3a91ed5e0c47d5e6b91f463440e03fed717d7ce98eecb7fae10fe8ce"),
    (&[0; 101], "c91106c58a10cd8783f2d1700b5eece0fe8ed06c4754d29a933a50354f703f4411f8bd8d5e1741ff84fe9d8102a83db4824c10cab88368340c112797822569cb"),
    (&[0; 102], "9d2da6373967339c9699df06f1556fefa0aa1d55b8873723cc5e3847a1f453e92252c7f6e792be46d6d1c416ce81c0606b027bbe993728e56a839ab17d31d06b"),
    (&[0; 103], "0ac8ed47f159bad0a4c1ff32f0f5c9764e416cd5cbc7cc8d1aae20b8a0283d5dec7f4074796b5d51489cf04adca1e466bb891169d8b0397ad1835f0a818723a1"),
    (&[0; 104], "526e4575b39193c0028e5b2b70e86931c287362db3b7b545ceb574792476c765c1cd84a94cc6f92d7827722b81b6e3303fa4546d92d762d93e68f4fffebed125"),
    (&[0; 105], "6999ad4e4415bd9a0e4786a9a16e045b109154858bde1a58f3f8614959b8923b5e23d35d54b75c87cd62cf4b705bc1cb8062ff096c4db24cbfe5ebfe54621d3e"),
    (&[0; 106], "69c0484949ecda308de1e4da343e84bdb883a96e2ef4575b9bed30883d692cfb650c118943b1419ba9fbd1db99419289db21f7ed0f1ee7295de7281297928e05"),
    (&[0; 107], "a3ae282f8f272cc4e9e928a004469d148002ea3bb83b43d5cd3d56f1e05fccaa06ec9b12db6a3717761f6cdd3e9ead13c72888ba5ba59c3da14c45ad21d1a0a7"),
    (&[0; 108], "7e34e16f21da00f508c58c24a6478ba345ae74a010614527931b7e14e7d3a6cbd3d3451dccf3aaf53134089df22adbf9e4771c3e0452f230bea71bb134bc194e"),
    (&[0; 109], "49d4c3568fee183ac1f5457ba0818dab455f119be9491e72393e712e94db483e715ade1f67a8dee515956624dea54bdc68eec31c297467dd460dda830a7f113d"),
    (&[0; 110], "d5ef4b1b21f8d4dc145874d0ef7993fa7ff988b47a1891d69586a6bb43a1275c1215123493fbc60f91a50dfc5057cba00042d38a3fcdaabec6372bc2b24791fd"),
    (&[0; 111], "e7250329ecf8fa11f25a1893fe4fc9f387d91dd42b76c8f88945873d2e90200a9d5ddd2ed625c28c550de80fb7757528ea592daba09b9132e55a2f056f092fcc"),
    (&[0; 112], "d7e2dd1d2e9ba23fc11810c760f7ba404f0dc5e52e0276416fba32b275ffbe84e39ae0463de935a5ac0b1fde9e05c7c25dc95c3ebbceba4d171595ce512ecd9d"),
    (&[0; 113], "9f5c2107ed0ac8d27fd59eb83b5705e27205927268b9873ca66e8955c1526cae8cb327ba0a5b0b1325acd1720a1e62442f9c8b0b773a7ea2695a83a3d94916cc"),
    (&[0; 114], "0230d301600872532b573fc1e37cf35ef2cebcf011d63b5cf6e657da9a79e3cce999a63accda9bca909d00830684e192c39c1e4f0faf9969024d7ff1e0ac85da"),
    (&[0; 115], "1b139a4a386f6c1f5778d6588e8cb7e923f54e479dfd80917611c629813a3f8f9d6ae2699c8aa70eb4a9726820517a4a0bb3255d9c44b2859371dd6da827fc68"),
    (&[0; 116], "3d6399039d03b95256660abe7a873d12e066e1d82fbaef67ba7cca24394c4fad0d14635c19c0b9e121384a939325c05dc908b7172794abea9d373ed5425049ee"),
    (&[0; 117], "4a110d74513916b6abdba758ceb80f380271b8563ca9030729476eb063af5b85909f23dc7c75a86fa68311dbd6771f0a0349bf0b2669a9a692a6f67704dee729"),
    (&[0; 118], "3760aaa12124fed9bc13c476928d3ddc0b96a11a3bf593f7ec9793130a61c061c3385bcaee5f16bb535ab2f516b91ad0e61999f40154350d13e938e26d3c2eaf"),
    (&[0; 119], "e60cebfe8361ee3795bdca647bd722e6d63b5bf5b69ae32b6e9e9a17f5dfc8de92ceacff2ae446c7b1b139b9202afc6b2c1c368d0596c2fd00ef45baa2b28175"),
    (&[0; 120], "99dae5bc79366242f01b4ec7c4af07542d5b6db675da2ceaae2d1627f089c9c901cada08226fa7637b2700b1f7f31a1904376cdf6b8227204ea17265cb7e0702"),
    (&[0; 121], "7545029268acae27cff811be53811457dfcefaf0af5331bab9095ba2934c74dfa6c3b13a02536fab9a2a7de525811ad2eaab0e2dc7c6cb14b0a346cba68ec521"),
    (&[0; 122], "60316b9bc188155d15298103758d765fc9f574d47c65ba677d7652bdb566c779bcbbb3aa5948ed0aab09aecd7e6bb754a0647011e1a344cd6a77ba8ff88e2a96"),
    (&[0; 123], "d08532c68b632021832f63dad72e7dafbf7deb97da8c0b14aa3b391c3a37def06086abbf38242bf8fa1b760bbf5b0c06bd1faedc05b37d27605f882afea66b5d"),
    (&[0; 124], "342122b9981ba951d9b16269fefe26b70417734ccfc207175988c70f026771eebe58072345a40b22375407860edd0b7b1bb2e6bce54593bd147f751f4c9eaf1d"),
    (&[0; 125], "138b8f5862272c11641da2db5f1c4bddb60848e519090d5072b59dbf14936583d35450c2058f731fddbb2800cd0322725309200ffb24631636702a417e251130"),
    (&[0; 126], "e8555b37207556bf37530cb84946bd2cb919563ce235a766c97a76e62b1f985651ff53f7bed9d28a2eedfdff54e87d32df567d31cfc0ce1c94a57d60041bfc43"),
    (&[0; 127], "957565d19abbcd4731d052e16e4a987b24e931862d6a43fdb4f8e2f3d5285823f8a8cc3bc2dfeab7337e91b1d53ec47ec04bf3ad05fa07180cad63596c19392c"),
    (&[0; 128], "dd61c02e23ad4693ce9c7d9a4ffaa3a5048a20f153f818ab5c149cfdfe29dd2b684df5de550ef3e64439f1eac4b6fdd55e7ee9a3c62fd56d92a0781781f6c4eb"),
    (&[0; 129], "a8ae6af5d982223ce5a5bc811140d1fa470612af791bba9190b1625c20eb8e18de1e27ad661f338e36ffbb710a38035ac6a19cff1a31eff04b156c40032cf916"),
    (&[0; 130], "183062c2dc166be8fd099b5b6abe8c578a9ae6c9407f7253f3f4504b7e8c2f3b37200f2c4957ae1c3694b98f1836686781655497349a6a1d9e44673502f8e162"),
    (&[0; 131], "71c140eaad31910d900087c36a3f48fc12d47941ec1d58b6b065195591a886dee151a875c859f879ce4c286ed2e1849cd8517f6de2ed089d63c35288f87e82b7"),
    (&[0; 132], "ebac5b8111de52576fd1ed0c54a35dbf39a2df8a272c03abba697fc969652f9dec4e00d4f0ceffc2bf0b6878d927f1ba976a1254489d083285de6f21d59c1a34"),
    (&[0; 133], "485e226c8c079c518cde922280fedffd02e15b3ebe5b39ac8781d80cba832434903456bbaaa2df17bfe00a366c73f03cd88aa04310110cd2ca038533dc403c5b"),
    (&[0; 134], "2687621f5e73212cc771940c7d8a223e6018bf45fd48b3bd3929b7c87bb7e8761efa857f55cc66e4716d69d9b243188e1d277a18b306aaf53233b69265c83bed"),
    (&[0; 135], "df5fd8e70debd82bc79caad80fd4239ff014765e3a4cb262877126f7874be52d72d80c84b4b2c4a463c2fbcdeb988063ca7fbb7157f4423f8c4aaf12259802c3"),
    (&[0; 136], "a0e034d7fd109e6095d1108d331deebdbcf4251623c6d02dd1161032ef7217a3b6cbdf1926efb6a3dfdda602658f7795af7c61833bbb92f4ca9456b04e5360f9"),
    (&[0; 137], "81d36373b74672dccae54cd8152465e91a29676f1d2ffc53ff0cf06d779ca9c0d5a439e71f0fa679906a238f8d24a12bc13256c10e3e5ec3fbd16b9fec5b6c88"),
    (&[0; 138], "fb180e817b650ee0eed572b4e52bf171f0543c565eb2c313bbefbe1fbc7838cd5ec0bf43d3233845733e5fbff3b019526b782575caf9fbdcd2f12055ad5d91f8"),
    (&[0; 139], "ba3f55a3d015fa499b60857e2b80f93846198ff3def95042929f6109dccf2c7ce0896929fde040f4cdd4c591b81fc2d822c2cc4aa37c4a5db3ed50f4327f009c"),
    (&[0; 140], "847e52fb21acee24c43b5cec3753143b99d48c83fed63a58f0651d069bdcebfd76f58817b9c5c54e5fef96ef12f401d49dd5d24de2728f18c01800bfd04376e7"),
    (&[0; 141], "de4c78c850eb184948a0a5bbe041cd89bc12d47bf855b0fa14939a7beea77cf6f9cf1170c2d0926d5c55ca95f805f09a786e1d1313ee1167dd2c156c8a8c8bcd"),
    (&[0; 142], "1c5ee40fef3c8e857b044e5bff152e648bd5d857e305733e8fc88f6cf1f5d4f9a263838576a1138e7f5e49da2785fb001cba480379b8cbcdf3b22f20e9b2f30c"),
    (&[0; 143], "f749c90f398410a30a5a42fa933f98712408ef37657f78ceaabd8558ac3274bfacf61db7cd5ff6bfd99fe4bac52339c84dd9348b915eb8041a0283028b0ba74d"),
    (&[0; 144], "eab730280428210571f3f8dee678a9b1bbef58df55471265b71e262b8effba2533c15317c3e9f897b269ed4146aed0f3a29827060055ca14652753efe20a913e"),
    (&[0; 145], "b910ef45f3c9896a3b0d4606e8a96775b0a49238dc4a12daccdec99e5d1ebb00800c750ffa471d03120761c1c88310c0f9213bc249b8342b2c8b37fefc9c0f64"),
    (&[0; 146], "2d39ca5177192c6f2943241e59dc7e74907ce2a3e98c935fe89a93f64899291a66d2354db6cb08f12d5dd37190e38f7dda941fdab5f0194a36186dbb76b36e78"),
    (&[0; 147], "d019e2d91f78e01d765797f399db7cb1e80d35a2fe59964d0e1b2acb6665a10907b56802535729f7d07cd62ddb4722258100e36d2789be24b97337f4647e7057"),
    (&[0; 148], "24afab0be802e42f6d9fa377f4e72597a687b0551808ca6d493d65d2b3f8c506a1cfb05646b72e080263e4bc315e55ce64f1631de3860bf9e0d31a176bf31c1b"),
    (&[0; 149], "62fbcf3edb79d06a941124056100d3eda6ab1e9bae4f7ed7af78a9de2d37f44e487f1a4067af3972f5c539d4c420e68ccb438304e2ce6c503af396bbdabf5bf2"),
    (&[0; 150], "7cf8bf09a093726e06d7459a88f9f323f403e3e2ba8fc317135da977b5154aef7bfe21392a842a88ca9e1898c483b8eed02a1c51b9886489800113d49684c0c9"),
    (&[0; 151], "351c7f4bd0678d1704c37945f2db60b2931efb6c9d06396a9c778ac31767a47c6790a2c9ad1f500f397a13a36fc83475a6f428bb30ed51618593d97d2a46d73f"),
    (&[0; 152], "10f7927505ee2795fa755454b99702d54081554b8ff94be4eb37b1025e1f71818249c2c95a1ea4cae370384d666d5dbcecaf5f2cc34634414c3ca552082aa353"),
    (&[0; 153], "9a93ae1374701506445a98818ac41ce0343bf6b21a96488b27091b1a4497b1907207291b5ddd82d299a331bfbe020932607f0e2485095d2d58db19fc0e451e96"),
    (&[0; 154], "6ea0975ccefa5831f6bf4ac5b06b2a14ffbd137b8d3e7a8d57420eb031bf72ef9296034a88d16d1e366c6156ce6575736ed9d9361876e922d688b8af73518016"),
    (&[0; 155], "7bba11927ce4d29e884fcab6a1690c1a71129bec976bb0d07b8418cf546dec739573f4e958d2b3e75a5b2feb286cfa2c468a4864583d822cccfc963a58a87dff"),
    (&[0; 156], "0eae674cf6abb1a248ccc9edb6581ff20ba28593892fd5ad31f4e5a099d44bc0a9070fdb603ec79509de199bb679b657411c59a48e9677da6f8e2dce53e46936"),
    (&[0; 157], "8e98aad5dbba38e8cec0f427507ace08b53ec72f0e289be7c4092674756d6002b8be1be6066496c73ac50cfe01e5d14762303c65a57e9ad93edbaeff28ff877c"),
    (&[0; 158], "5aae44b9e0ef119dc041323b4956db16dc75b711d3a04411fb5fb5cd4901f5e3f11f207991798e0cc366029c4a42101e050e7ab59fb118b5a0cac864ed39801b"),
    (&[0; 159], "ec5eab410cd8d57eb69ba4057be88a53d65387282caa8a3ecdfef26c2ac83cc2104fcdbdfe067de0f20f2ea2d3dfe6a33ee247a3d5736a18afa136c78e5b8585"),
    (&[0; 160], "11a3831efd1db4d0cb407469d5c5c1f21391299ac8060356af9468b7e5db5c875198be403e59dc8fe2daca985cfd0df16f5d04a588dfb4362be62afa2bc66c81"),
    (&[0; 161], "408f172dfadc01ad2a27638485352c2e8faf0fde30a1f5e998f8603b1049e4350d1684fe2ec780c208bf784e4ccacf372e1bda3c37cec3fbc4f31a5810bb06a7"),
    (&[0; 162], "11d4ab2e12b0c9e7089fe5ac2ded02b00f29bac121ef80520d68c9746469ecd904116c4b2e908517ea77182c38a990f283a6707c4ec5796827632c5940ea8eea"),
    (&[0; 163], "6f7bef3455b35b5ce9ea8b9c2478768349e5ab3fffd3f606b3aeced66b4aa88503f91df1b287a810ff613f5f6208ccadc1c65b6c434c384438da87fe1ebb7b88"),
    (&[0; 164], "640d4541da980e973c5a7c28da297bd6239ff8b96641cf09c90913c65595ba31a28d2bfdf0749ab46c26ed4a7bc36712aa99776d0649d8d32e2dec73933aa121"),
    (&[0; 165], "d0a8d657e64fae3ff4a0dfe832690c505853e057a654399bc6eb83a6bcaaa4c2c7b831727c3d22bf15cc72a3a636b1cb4744d0c28b7d6e7d613a865f1cece1aa"),
    (&[0; 166], "6f607d6d03667068d41664db60ec6d8bea14ae362bac5a6089e63899439555605385f8439855e47f41b2faa6c5737bd055276147f29b4a7940aa5b26c88c53f1"),
    (&[0; 167], "af0d5cbf6ec36eb71a8eacfee29ea085796d44dfd8201bada985e80c9beb60fe99ec61eacc77ccfc86e820abb33f6aff1647d708c62e534e328bd1918976b2c9"),
    (&[0; 168], "46cb4ad276fa3106b74cb8d805fcca19131a5be8596cefdab81965b5df30cb20de3bb07f3198bf95cc2ea124869883da1794621685315694e90821a03d43ebba"),
    (&[0; 169], "d97eb1b8f917cb5868f97df91cae4aa7379d21b49bf335a92a5c7d33cb1e7a999d97cb24286b721cf337e4c8950cf9b591736e812293ba2eb520ffb4504e03f9"),
    (&[0; 170], "950c5d7158f24725bfd82093fde610fc5f25d087882f15e4d147f5fde999e63b058e3d1031785c8e0e038209202878d35d88dd3e7a0df9362d7a59c823de4089"),
    (&[0; 171], "aa584777e15f889688381c368cc403209371a36082c83fa20e4915feb1190a195f13936259d3283f94e9e964d33707deab84e7748462c20bf10708bc3614a40e"),
    (&[0; 172], "89e7f01faa136600299a8588abe4443013ee20ef4b73a78a30045a343ad0152a2c4171c0679438c0ffac0b7c6f2e7dc7f9a5af75381f4887831f75bc75bcf7ee"),
    (&[0; 173], "1e92e656bca224a6a245fdc519624453d4b1cdf56c7c2576c006b6356ae58a8f6dc2dc6377dab0a27ce14bf389ec2671548cfd088cd11f8672f291e47026c2a8"),
    (&[0; 174], "252908b023f484ddcc6462f635ebe53d4a7a1e8ddf3fac4575d2e23340d2cd1f4386cbd893c147ec7413802af4796ec6985e4137b7b42c736f3124199529d186"),
    (&[0; 175], "1dcbb6cd882b14c3cd06d487b3e33e333c9ccf13af76016fb28967cb7b88f93d0e74cf9b61fbf6c4e73b3e35311b37144bc573bfbd4a2965274503daf0f6587e"),
    (&[0; 176], "e6ed51d6c7635f34e52022ae71ccd3e50d74d18039984e76e2f9886e7f520df4179f3724ef617125f90ebcf107644e2ba14477d4f151d8227868520e0a30050f"),
    (&[0; 177], "4506f6ef1956877ede616d6f93d19fa7277a039c74c8efdeec299ab3a1bd9eb00cbc2ee525568782dcadbdb9ccd28194cfd1f9ea08e00f97290f1d8f236cd34e"),
    (&[0; 178], "55663c2ecb4fdacc0263359fe7c80c63196dfe719f98f4de8d1dac42093b31ca8b52965e67d872499b4b5a55cd637a0493ee39953e811ef86e87c2c8a4a79bae"),
    (&[0; 179], "69e6acc415a65914ea4460c612ddacc0de8cf354cd236194276333f322033a33ba646a4bff1c50eb25d07912496d2ba3e0cdacfdbbae6e9c5d47a11f2f680fda"),
    (&[0; 180], "5832471ac24c08a104b9260f9263c989f9dc512a9a218d2b9ca465b02ac597a9bb6089ea801ee11062f471f1264f83d6f0c2f23beaf3a568e2c9e2415190bb1d"),
    (&[0; 181], "0c43435d2f4b3e3bb260ded1ac9567194d6cc4887bef76e9af08a5cc5d87d07ce74faed6bf5198ec26c19b6b4abab9f1820034edeec2232be1214e48124aea44"),
    (&[0; 182], "5ddb9f59af6584d307b5dae0fc83153435974ade36606d7121e4bc0adb5d938e63b499a361a3b347bc083e1d51242015b30d10c9ad234aadfb730b229a7096b8"),
    (&[0; 183], "79381935a83f0008b87fdb125ae381b568c8c046a2c57547e011da89fd59dd1af04ade893a6b0fa904d9daa6cc1515f89d12fd2cd5f723853db5423642a34d7e"),
    (&[0; 184], "a364176a3f51534755dfcbf5a2b7af7064d0f854e51d9040500f71779201c64d56513a5ef4285479cad5486bd05eeb72ef68f3a2c772455df1ba1a8eae3e08c9"),
    (&[0; 185], "4f04f0847d7feeb02f45569ed015c5c17b8144d973c9d2ae9605716e50056ad40635c61e5d9ca7687e23a575e18cdd0b7278025293937546f88aef721912244d"),
    (&[0; 186], "008f453e29f4dc23b63d95fcb5e1ae74ffd068170bc3ad548ca5e150c77d13768c9db0bc262eaf02734a9b00adbe102d57a9bf323aa913c33e02350e8a56c380"),
    (&[0; 187], "4b146c59dc402e4538e92513ac510b7f8bd83f1ed80e2ab20c1b318c2f7bdd89b7c136dd45cce6607dac2f6129f47236e6809b6626f8a33a99b8338b292b14ac"),
    (&[0; 188], "82866b4ca64e44444a5f00fbac5cbcd5c46aed0c75cebbaabb0796ad653c10f82bf7ed0a2744d376be46878ce349ed6dd23d02244def559d7bd540216433358b"),
    (&[0; 189], "f5e8046aa4a850dd9e98acd98cc9a8757f667a6290140304602ae9c8a3c7f00e19bc728a64cf9f65ae21dcab2f7c9eb39aa8aa4fa72c1de9c930cae01cbbd6e4"),
    (&[0; 190], "dbd70ee7b3480324c6e3622d546420f6f546aedddffe84f20dbc73a0423f6690719015ad4779edfaf0bbfec3c3cd70f1921e3e7f97cc2d1cd60f05bfb2c6ee65"),
    (&[0; 191], "bc0ad0fee4f34e76947c449f6a46e70dcc46f4ef0f1876667463ff07c198bd2a67230b4f31aec67a721c97b1c7d34eb7bdc039ca4a25fc71f3b875734a6d7a0a"),
    (&[0; 192], "b260fb42af5b0568f8560c95386923c6036b80b2321808d281e5f522084535622eca5829d135df5361efb4be21a42f81168e78d5e80deb4c91bfa8f5aecf3474"),
    (&[0; 193], "0e7f366ab63899067779746f6caff9f6f03d8ecdf5ceb88bc514f354bd820f10a44228620e07edd1f137a7a846420f3d0b3108678619d3dfc92f6bfa5c71729e"),
    (&[0; 194], "519f0425d722dfae7d3dc1a94ca5ba0f86860308b9a81745bf0ea6848b659d1e6c818be5d76b8784f67f794d9c4cc2a084380405504baa2299d0a6b7ea256fbb"),
    (&[0; 195], "48df6736e7b76fe75d89b2061eb68516303e1a6f9b99aa8732ff0b34d7047353bc74842a610bd4596dd806ceaeb6754ba7fc4ea27b3e724287e1fedb3de8504f"),
    (&[0; 196], "f1bffac42cec01d0b81c2bd15d0a9ed3e3fb61194f972e8f14e8b7107328b0088326d3ba3a541b48f9c35a984298f3b13cecacd245459550bf7fd7046f964fe5"),
    (&[0; 197], "6696aea5d0bf590db368886ff4f3a19096250c8b1d8ec27a54b425427f0c4e50a047ca9baa1b0c7899f682654c7cbe2d57e777382ca500e84597ffc2e8d7f9d4"),
    (&[0; 198], "78fcab8df650d1bf31d94d501d99abac3a18e7f7aec164ee458e795878ec680912b25e487448f1642d533a195254d4b7b1a4b8f265a4d22586aadb33c9e6d42b"),
    (&[0; 199], "24e8397ffdf2d5d33f5c32fa053ee96bae298a8194caa558758b6d540643e82ad47529955f7d1562be8ee91436d4ef6393adf6a6048dcb461afaf96f9a70982b"),
    (&[0; 200], "b5049e48f09433fcdc1c1b59bbd05c21bc4e1e3b327afa4ee55a0db1670554cfa78f33db57232c047c9c64c3fc42f8d8a6ef750a98bdb16a7733f5ec26c71ebc"),
    (&[0; 201], "bf0a9760852dfd9d5cbea19a2cd865299b63020db1908919e9063c1c5bfe52f7d8de3f46e9947eebfebf09c8d07777bf8d35db3c66648146b6566a5319da4f57"),
    (&[0; 202], "8e6ea61c91c19915962cf42d1ad85e6f6c0385254f9527e820abc88192c67246b42500221ba33913c3594b07e11d5c83026daf68067f0609910c1daaa3e46e62"),
    (&[0; 203], "25abb870356c1928c596ddabfc39cf8aaf10041cdb509ac818e4a449f3fed8d345b99ab6fa078c8fa07b9678c4d2c3cf6f2e027cfb9742426718db7ffd22f4c7"),
    (&[0; 204], "50a6819105717292a77309faea4663292b9eb6c7c4fc8aeb8a1c5a1d1a12fc7a519aac8ea40f491ffd602a584f3f9a06e52509f67d696aea4d2a46c5b8d7fb13"),
    (&[0; 205], "5b9b2df32230438786113f1bad755778e20a41d39e4f4d3716eae2083fba6574a0aa3fe0d27aa2139720b3f230fc5442d1863e9858d080fa01fef8fae673b725"),
    (&[0; 206], "bf5cba6fa8842188a9cd3438cc3b4d84a8e43b5deb8eea228357ac571008271b3210d296f0a41e0050a7036ed49bb69a66bdb73f29929aa061ebab80e3c95b7d"),
    (&[0; 207], "26c06003ad8aef41761cc3817409d44ce1c8ef507a648f410c2ac210ae0e700d4f58e8f52dece9af90a3a7c324e3679629b818b2d5aadaedf04f37a7a729c641"),
    (&[0; 208], "368267c8d896fc34e282150a6d6ee9b63820c475ee55b08a30c4601fac13c04613a90506bbc871daec27281f642fd6a05519e970d2eb04bedc344c285ae706ca"),
    (&[0; 209], "bd4a4be21c71c0586e3851aed2a6c51b35c0226b3d0c44f196d1bee660c0e9d68f1fcaad9ae924ffb197d0b1549ed00dc7baf8ed1ca35968d594435370995f96"),
    (&[0; 210], "3da813656cd2d1566fe41abcbe7d30ca60a9915607d021925bccb20aa494d38279767dfa74baf7bafdaaf2d99d83d68b1ca6150d99c936eb99d8bcd0e400e22e"),
    (&[0; 211], "25dc3b71b0529fd04fa6aa33fa0c4bd9682eebeeb9031b98f7dfba517ed78548d128283212a7b351df91a74371e1e78bf76d2f2a2638f9c9168b3e9d8f51035a"),
    (&[0; 212], "d7338d22983b808e98a15e3a9e815c8aaf323dc4664b14c386d17e7368cfa61e33e5c8fec112f5e6cadcc46dc978030f1c076d55757816dea57fcd7c94031a8c"),
    (&[0; 213], "675c6c75bea032a86ab6c2fc31faa8f9254c701a428a5b972f2a8977497fc4c2efa00cfac0c50dda7e90257ff8fbf6e04eebce7b55786e21f2aa5906a530c420"),
    (&[0; 214], "7472ee1198bb806d2a37e57ac7a9b860c27652cd7b793bef90bf16a251ed869447823d5e93ae95287f46525debca927ecf7e6d727f08ea4dae007f118b91134b"),
    (&[0; 215], "ef048da1ada3ac7c61a13eda735c5455001fd1baed25ce7e27647b701a5ce47c3c4b9d4eaa82528df8061fc461da5052971e4169087dc7696972d6e76eda2198"),
    (&[0; 216], "504f07ee16c7ad7e5fb9790ef0b9a7f28ac6f70327f9b053d79241c1f66d50c812ed4c77ce9819b8805316e92fb3657be85e437b96b21e2d8b9c56094a60e0a9"),
    (&[0; 217], "35267282e62abf126d99419466fbaa601f6dcb386e9cc245a5e1ccef8b21b90ecba49945019d54d289076759cb95b97026cda3ca5b3df7cf108deb4b2d35c018"),
    (&[0; 218], "e78ea781c5ab03ccc009cbc16178fe37c8a4c68433ae85a4f21d0fc8b6ea4d96ae6c276fe9ba7e5b52d1312d4745836c4fe394578d15e9de7bc1f57e1b0a5181"),
    (&[0; 219], "70380d723b3f4bc906330e893a14bffe37f1476c12500b8ccb20fe4bc3e7f4b6ef927a1cec7e14966b31d595e14de6811da7ddc7bef8433cc6715f227c42e566"),
    (&[0; 220], "1859fc43615519c194340a933b31e7fd3461d654159d2f94fd4cbea06325446779f653d02a764d82b9b616a802db1241e1f1c10ba3b0d441e16136b941ed64e4"),
    (&[0; 221], "b359329fd9fbc5843db36c7f0365d63ed80916c143d5ef4c4d7a408b26784045a555814f875addef1d7e93b88a2243c53b075cc476c6153160881fdb1f1ef50a"),
    (&[0; 222], "f48b0a64069a0736848606b5640edc6d6b6a47099aabc9e2a41d593bfbf610af6326359ad0ce0f740b3288160ee4734e769c2710b9cadec7b6f84c7bbf2ce9d3"),
    (&[0; 223], "b7c1234677c6990ddce1dbdf49b80d57edfafbe97ff8d73b6657899667e38f1e94db69e7e8da607f191f2ee6b01c21dce378e640e00b34dd72350741085f9741"),
    (&[0; 224], "b192308a3472a120f137947eadfe18e9afa03965fa9aab5b61558beecd75d242cabbb16c0f902ced19489ead86bcdd05d2d0e37bd3ce29d74626154135dc697b"),
    (&[0; 225], "6d361e9424227da8e412c17c4a8ec8b2d98f3d9f73267b4b4bda341e8d0193fec0ebbc2e51409d987d04bc12bc1077ff3177bfd6c169a5deca23bcb6a893ccb5"),
    (&[0; 226], "50be965db4b37deccf906d588f22448d4be0b9541bb99dcb2429d87755665dcf7ba650dedb8b3d6b799a232817b4eae606748696549528e1d70121ec10acfdd6"),
    (&[0; 227], "a0e898f1e365da37a36e13c977094135bba88a21f4a082395b2132766b00f5a7069d96409e3718fa6cc35d25d489861abb0536307bd24d85ad9ec579d4f55ec5"),
    (&[0; 228], "a1addab334f17a9b10929e1bc5c0d8d50b76960ebf8b4e7448797bc0d66e359757b68810a468681e07df89cc6eab5e4a83567ca6f787df164cb40b0fb2514c9d"),
    (&[0; 229], "02d15afa3307ca0c01216093a0c8350da2358e0e9704ccd5875f53122adc7ab3c59b064cdca8d509c8f1d09e2d3ff9eb7caa9b503ce57d412258a7e24e24096f"),
    (&[0; 230], "e58899aeb1a8e982a7dc028fa5e91a9730d1d4ee7c0f0fa0cfd9b757a730a87ec47e51af7ab988224e5515211a90e10d02e28278f51334bedb222c22bb86d3ef"),
    (&[0; 231], "6287e5fec63d930607323174e9039fddeb917272ee018b7a2b11876f5a1e664f95dc656253b326714bf8c487d51193c033aa9f937711e95e9f05b9b7e5324514"),
    (&[0; 232], "559f51f08a0a3d282f1c7666062c6cb9039ee372da3ef78baab9b3840e4494f32753c94285cefcfad9a0b8a88b1d1e3f5978392ae14b6612a06d3f50585e1621"),
    (&[0; 233], "4a598196da25abe1fda9e50545908fba64b1c1ffb36e9ff8b664e0f46acbc0f3b39678bbedc2b2405e525f7e088e336e9b0ad2b6dbe2b0f5d7caff487b991d44"),
    (&[0; 234], "18587ea5ebe9b5d744b862280038917c95e402e49822222475b063e6fc1f1eed5e753a269d500791c259bd645102875dd5f204cf40403c115c9528821a375cee"),
    (&[0; 235], "de288c2b12529312ee8bb0ca58b3b0d985e7e8454f6b9b82d4319c531dd664b22ec1f1755a4ab8bf5aa311b3b2535273f48d3c4dd4a62c9119e8a061cd498132"),
    (&[0; 236], "0fcc1aa99974c8fd0c5462db2f03243bc46528ceba44635cf659e39ade67f840c1f6fa2b9f1102d0030ec110b7c73fad0dbf0081170bd489462a5fca39c01652"),
    (&[0; 237], "3ccf5eb16c13ad79587b0fc48999826b0e832f24de6f97a63783c5f115897b4546c6dd233b76cd2b515d54cd3f5f69fe2958ea4e95f366bb1830b3877a9d2a2f"),
    (&[0; 238], "e1344f889e039e15d7e9181d073f204d9ae584fcf5d36b6cadef6e00a354e0f9f221a8996bcd49fcd9e820e0fad94202d039d93204cfd83965573243bb696494"),
    (&[0; 239], "8fd86d93c8e070d8508ecbdaae0eae4be13a5cd4214d6c3c2f2f046dc5b5181981e3715c7c3aa6c775c7f8621b91b9ba80bb97243a29ebb94542db277dc31328"),
    (&[0; 240], "ebb3cbb3412d563a7a26b1855c86f3a37fa5566a9be197985303cb038128652fb8426605b287503e6c93ec01e7cddb36903c1740600e7c60fd2cb9b31e657cb0"),
    (&[0; 241], "e18fee540fe34c153e1ff3efe093e9d0bc718ded8d3cca8e3b0ff85402a32fb300d42cadd3f6612a24a456bc6e945c1989336a49d5e01238c21cda5b41660a99"),
    (&[0; 242], "926cf0bf05669ea4aba607dcf4d4be37c05bb1914c69645347f0e43c76501845d062e29acb01200467ef0701b66a536384f99375be4f14f419ca09c2ee7d2df5"),
    (&[0; 243], "4d482c7eff71cc73bd22ee8f4e68f71647e7863a0441edab1bf96966787e77417a186da7b72be57d0dcfbccb126e5fe0bc4098b527fc47c5fb0543ef1fc599b7"),
    (&[0; 244], "51515cd4b3080528482ddad839a87ca6b6241681fb3b6e19cb1f8fc501f01b0ba66ba02541aa96eb44190862ffb89fffff90e1c546b590da24c66971aca7a30d"),
    (&[0; 245], "72f2cb627a921d1abe3a96fc1abee1639900b733794a1f187d1159ecfcf1f9175141473986c1fe17b4624adbe57820e9d8a9eac35893a66f7d93aecf6c14900f"),
    (&[0; 246], "2f775917d2b92c5c67c4763d55c0543d80839f8321346ec0aa9465e78a0a2b6784509819c9362ce9ca32262c908c3c8118f0b2e6254cdba4e7aeeee4c20c71f5"),
    (&[0; 247], "84a5055d8c9f888b65953c936e2ec819ebba95c82bea496695b4216c9c7ef9462ca416544c8893305dfbcff371ed1e7c760c8425e19e08931c7f56e55958c8a0"),
    (&[0; 248], "f8a79f64cba02c5187a515122a4691da1fdb4a6d640883e77c93d7de259af210b43449cf4425534763d6d5d01ab6ab55dbd6d95b50c41a35e1c8e5396ac868f0"),
    (&[0; 249], "36e00983b8f0d3e10d896e9b0c1da7e4710c840834562bd69825c93a52014ba3bab2fca444b7c87649507d01f27cf39137f4c59e9352da392ec086fff0382a59"),
    (&[0; 250], "74c30a01ce13624f0676edf92219674f22a75d0d633ecaa31708dc65502678c8e960f254884286dd2b5e9cf27772b0840107d7e34660857f11b85eaea85a92eb"),
    (&[0; 251], "03dfd4c1d29fab355d1d1eb05bf930445cf7294677d6aeb048092113d1e371fc0fc72cf2e8b8f6e4e077477017dc25f452495d48629556bd8913dc9abfb46295"),
    (&[0; 252], "5de2b70e56969df1c09d84af48ed80513bf6b56d7b8d454083efe44e510796d1ac1feeafc0cdbf3aed1a6c5409dc2ab86be156c6509afacea06b84ea1f8e7dac"),
    (&[0; 253], "7b3665d5b5e4b6bb850dd31262dd467dcf9e7f413c9d77bc78ba60ff0297568994c4cdf20a5199b3bc3863b13d99d4c5b297fdb754fc2e310cf4834147e6264b"),
    (&[0; 254], "56ae4580e70ef0e94003e0c3be4830f0bc84fc4f25a784fd72c402eee2fb860ec44b72c9dfb07c04a417a4cea8990780420f3cbe088945250539885de180754c"),
    (&[0; 255], "fdc6dda8323aa417e3053063b13eb6e32f40b15c3eb1416bb43ea864d0e02abbe9355cfe152ea4b84b6a5365e27fc72e542e76e3bf1499d24693f24e10077c33"),
];

#[cfg(test)]
impl crate::hash::Test for Blake64 {}
#[cfg(test)]
impl_test!(Blake64, default, DEFAULT_TEST_CASES, Blake64::default());
