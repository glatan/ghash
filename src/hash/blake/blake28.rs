use super::{Blake, Hash};

pub struct Blake28(Blake<u32>);

impl Blake28 {
    #[rustfmt::skip]
    pub fn new(salt: [u32; 4]) -> Self {
        Self(Blake::<u32>::new([
            0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
            0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4
        ], salt))
    }
}

impl Default for Blake28 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u32>::new([
            0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
            0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4
        ], [0; 4]))
    }
}

impl Hash for Blake28 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x00);
        self.0.compress(10);
        self.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake28;
    use crate::impl_test;

    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); 128] = [
        (&[0; 0], "53f6633363b0cf3d4253963628555b5e8961339d39f057fc3782471b"),
        (&[0; 1], "6a454fca6e347ed331d40a2f70f49a2dd4fe28761cedc5ad67c34456"),
        (&[0; 2], "73f6bcbb3ea69c65eb65aae39874d5255891c2b19be0a8101fafe9b4"),
        (&[0; 3], "8a9e1c2e06178a172914a568cf051c7ce9daa1e2ac3fa6ee9dfa69bb"),
        (&[0; 4], "a96f2a6a0f108c737f92f153be850563006717376180056b9342f067"),
        (&[0; 5], "a52c3f8898d1a86f95bd373585ffb53d2a8ca95c7eff7ccd09d570e5"),
        (&[0; 6], "d1c0a35e8d753d0da5445b95423f521f6ab8d217c63daa68ba1923e2"),
        (&[0; 7], "33bd31d2bea79e125c4de560c57c3637a0401cf188c29d5cc6ceb838"),
        (&[0; 8], "04c35ea748874204ca63a27c3073c19b1b76e63ef92b36a0897be93d"),
        (&[0; 9], "725a3da81012e7a9a5c45e32cd33ce04ac03aeb9a0f2c86fab80c00d"),
        (&[0; 10], "9c2a3e32eefda395bb343daa44ee70cc4bbdc4fbdf6f93457c27d156"),
        (&[0; 11], "a7daa473cc11ca2aa6f7c6c2e0244e19dae94fed107a7169fb7f4387"),
        (&[0; 12], "6fe0aa7f241bac23bf766b53a5558c707465600484183cc0f9a34ad7"),
        (&[0; 13], "fc2b3755e7e93c5fb042e65671a0c8434774e114352ceb745f846715"),
        (&[0; 14], "eb2bf8bab6802af6c32d73af3fea19043b7464f71b3b2f6cca3afd1e"),
        (&[0; 15], "f9258b8ce58554fa14f715e474ab034e695a158f5e77788aacbbd665"),
        (&[0; 16], "bb3f56364698d5784d52a842ea1baba08b85e720e0ca596883be1c6c"),
        (&[0; 17], "aade9cdc037b93c4ff5d8d303d347a8fd2bf9073fa955b3003fc2066"),
        (&[0; 18], "ef8e8739c12961b43bf374dc3f6d1e96cc69d7b4c615983301a49848"),
        (&[0; 19], "b5f2aa334b1c9fd8c78ccb4ba269352c7cbdeb934b9076af45dc163f"),
        (&[0; 20], "8c7e3e6b2d15170af02fd52d4ea611742c3a6d2c9361edd97014f9a3"),
        (&[0; 21], "cc74c3058c503d3f68b77791ecff17b6e173da19993bd126b5fb8ce4"),
        (&[0; 22], "3a1d8e0d8cc9f4258bd95280f9f8076c516c99953a755c7e43acedf0"),
        (&[0; 23], "930788629eac55fb05d388ce2db6c558ec7b4b6aab68bbb4f74ae9f2"),
        (&[0; 24], "b9a1cb4a69cb77f9d054ada35d4da161c03e6c358e6545b7fb4b958b"),
        (&[0; 25], "d7c501c355ee16037a4a38207dd24fcbfc86a21389c344ec2730e45b"),
        (&[0; 26], "8023a5c5382098c1abbeb37926a9ef46f49440cfd4c086e7bffd43df"),
        (&[0; 27], "3f5f0aa2f731bfff6a288e6403e9ca6b0681ce2e5ed1166bc21a4344"),
        (&[0; 28], "90c7bb37f86ae0de942b4f92e95ad1875a62949f305a5b71403dc5ef"),
        (&[0; 29], "96d0fdcbe7d2d85d009052bf3178ab303316e0059463c83ffacca4d6"),
        (&[0; 30], "3e01d65ece51fc282f57fbc7f232d36927d65cf32cb4dfd432c68440"),
        (&[0; 31], "e4e1a9a8948d6b894405cc20915e4912a4577933986033a7eeaafb6e"),
        (&[0; 32], "c0b60c6387afd57f3781ee425ef1bf5419570456289fc13829642be6"),
        (&[0; 33], "815d5d09b49804f7850ad213e15e0d27dcd6ac02e31535ccede84b74"),
        (&[0; 34], "1171f46ba069e7086ef69432ab02888fe7ad8bbe57f512e231246776"),
        (&[0; 35], "485c6135c66fd2538e95317208b71221b0cc12147602e11934d06601"),
        (&[0; 36], "5e2f48e10e5dd2f749e647f2c8dff8b67651fc55250292ff69863318"),
        (&[0; 37], "0ae59dca9339b978096ec70bdadc485edb546cc36d8abc1e57fe7d4a"),
        (&[0; 38], "e3ff28205942195b260271217ec009c6373a48b666fcfa9915477c9d"),
        (&[0; 39], "f93551239916b858d184035c7d20f3a1cb342048c9f4bf64bba4b8fa"),
        (&[0; 40], "2dd52f14308835e24b39764400e47176fc619bbbf3b955d3af15c3f1"),
        (&[0; 41], "2f09a345c8d9064e30436bca41d4482bae245839aa7f2f96a8e5beed"),
        (&[0; 42], "b7e5f493fc5d3d48644941070c3a80353c288a972289ee94df67aaf1"),
        (&[0; 43], "7469ac06ce46b13cab3e50fcd6f7ade225d02ea1938eb8583ccb90ed"),
        (&[0; 44], "c54ffe949ede4ccd14b4d8d653ef17664df72ac950bd9784c5c79d4e"),
        (&[0; 45], "892ee2e3cf564606e0c947164c0fb6f1dc2db954ae00c191c6b72d92"),
        (&[0; 46], "889f9e79e9fb446cb971013cd0041eddf8756a55bd3f5b0526f2fd19"),
        (&[0; 47], "429b3865e8a160cac0e4a97c0cfc6c86389fed29b39cb915668ccb05"),
        (&[0; 48], "84522304e6078d16f5c7752a292f355fcaf1d7008d0fc6e01306cb65"),
        (&[0; 49], "ae6cde31d013075a12136061ff4f7a46d8240d07d3bf22a6624de7f6"),
        (&[0; 50], "05af24782500fb002276a36c15333853004d038a4efbcf0d212e5184"),
        (&[0; 51], "38087b70b7016e632f0534e220befee431d52935ce1bd5500dceb661"),
        (&[0; 52], "1c1bcb5b2011b54b122bf1d6513c5bfa08391c833ade69be4e6c6324"),
        (&[0; 53], "d4ff5b9bff6845d60d37ca2fad047b146d0e03998d72718e0371ea9a"),
        (&[0; 54], "72f2b5e6856522009185d308ce01ab3a40ce81e150b20eabb3b2377e"),
        (&[0; 55], "895406f150844ec6e96da9859c1301299970735414a286b4b1e053f1"),
        (&[0; 56], "b37eb794a950bc1b49666902d0bf5c90187aca4a9d1fd16c588858d4"),
        (&[0; 57], "aadfab13dd4c0e65bad491a32659002b9a65bfe45bd2b608ac66d59b"),
        (&[0; 58], "297c5549da92d110920b2477ae7958142fffc867b8889eace10264b5"),
        (&[0; 59], "a75dbb544465d7441dd28090163d1418a3dbc1cddacd952999e4cdda"),
        (&[0; 60], "9f6ee3588c40256e38b9204e4d95a5502e0199ad9b2b4c24adec7853"),
        (&[0; 61], "aadc0a6d899dd30bcb455498dc5f4ab36ff46bdaabff944d9457e7b1"),
        (&[0; 62], "2b74b04449e4d540c820bcc8906d1cf009fd5a52db71dc1eeb39026c"),
        (&[0; 63], "57156b56c95bf06f1e553b67bfe4e268b4991a94b0ceafc83e88053a"),
        (&[0; 64], "fe8703934f844f84e8812cf46fbb076931f2a1114d57996bdf9d1be5"),
        (&[0; 65], "a5815cfb79416e7ee40aef29e09fe60bb74b448c77d06939db6695d2"),
        (&[0; 66], "3e68e42efb0f5466a455277ae2aab044eedde26415ea7170f9121656"),
        (&[0; 67], "2bb5335c7087d3b3e7522b4d29581b5101c67a9f7c3d16513c8051b5"),
        (&[0; 68], "5757db348f95ae9a2b734554e5408a968c1f0ef9edc27ce151bb4f3f"),
        (&[0; 69], "e0ef3dcee019dc00ed40ca92728b828f22ddd349d223cc45578920bb"),
        (&[0; 70], "1b92b75e8a18662c413f59fc0b28e324a16d7306f409e604aeb4bcb2"),
        (&[0; 71], "0b8dde17ee046e52627f2e1442862cbbf10b97074cc01bcaf2ea96e1"),
        (&[0; 72], "6ec8d4b0feaeb49450e172234c0b178e795bdc18d22420a85b6f9bb9"),
        (&[0; 73], "d391f5cee6ea14fed2a0a6739ee6f0cc933dfe2898f5f033e98ba52b"),
        (&[0; 74], "ee2d9df63679af2267979569ba6cefc7bba789456bf71af23a1c2d36"),
        (&[0; 75], "0b1964c7175f88c1adfab1d8f91c372e6cf3c5fde34c5ebe3e2cd436"),
        (&[0; 76], "f8910857bf756208046fbeaa7e18c843f690bb255defdcc4ab3cfcc3"),
        (&[0; 77], "4f1caf752043389f6df99b11f417f347d9559343edfa98d9b6e66020"),
        (&[0; 78], "19aa79da6bc76f8198bfae327bf77493d718a40c7da92cc640e20196"),
        (&[0; 79], "db9ca9a4d711529f11e636de7b1261bd94709d4f2669adef769c0205"),
        (&[0; 80], "915f90895baeb4f050e822bdf58eabe17f142f7b6c4722de9cf9adc7"),
        (&[0; 81], "fb65bad14d5878b4d5983520e22b75479f48de12feeedf14416f1d90"),
        (&[0; 82], "7d350be672f3eca34c548f2022ee9eb55fdeb9bcc0b6455e69f49c65"),
        (&[0; 83], "c1a3de5900b1de0cb8745bd4f22407db44b471b4f4182bb42e421642"),
        (&[0; 84], "39890f996ce92861a0ff232246b99c95b883e4686deda036b0c17b7e"),
        (&[0; 85], "dec3ea18e71f0bd143e9355a282764acbd1b9850692f122fa4191ca9"),
        (&[0; 86], "84f8fa38c7eaeba8bde9742ef30e23a4a1fb2f1ff2db8dcc3e1347e1"),
        (&[0; 87], "9c054065f4b686d0da0100532622edfb93fe7a12284729518c83293d"),
        (&[0; 88], "74b005f74b97cc2c1d45a4951115c7c4ca9c652c3778bd21bcd0388b"),
        (&[0; 89], "0211be29e62293d08b5c5666497adc48f8a9b06767943eae580ee0c1"),
        (&[0; 90], "07161b1b246fd52c696f2bd57f8732174b9a7cf927dded59d950d5da"),
        (&[0; 91], "f1057c0caa88c6eb1a971d4d80aadef83ae32113c730f06bd90717dd"),
        (&[0; 92], "a227c69de7ca3fb48ebb0e2660bab500753bc94ffcff56ee6cdb019b"),
        (&[0; 93], "14d42d53a2cd97df33cf0f6554e3b8a1e92c29d0d2d0210d0066dd3f"),
        (&[0; 94], "2f014f693ea32ead4c0834727ad0d493cbf07c3f306605aaac1ffffd"),
        (&[0; 95], "e9f6b7010a812d9921c76637b6016545dbfb0db6096cc7558f4ea649"),
        (&[0; 96], "a801a5ad0ccda64795c7c43390384b718118d94a88565435f18ef697"),
        (&[0; 97], "218a9d954dc855b15f2d5897f6c6e90a7c1179725c4b57085ba1ad9e"),
        (&[0; 98], "e67929e73ed4358eeb128240c7d34331451f61d8613a6750137a7396"),
        (&[0; 99], "e13debc284681f086d6b3ba4686eff756eea7d09917fde230905de0b"),
        (&[0; 100], "e2a6eb7d4543681ca5d9e294be109dde43088128d64019694cb57016"),
        (&[0; 101], "b9b5130f7136840f96bd74b96cf7861c3af5ae84da6f7ebe9c3a9bf0"),
        (&[0; 102], "49a0bf9bc60fe11bb0d9335d4e5285900bdca81be9e6e18c5b984c91"),
        (&[0; 103], "81005a9a5a8bca107344ee300ac8c647cda47d0688794dc141cfc943"),
        (&[0; 104], "223d073420e411b25c2e7e29832dd494249a7dc6af87d92d7f894424"),
        (&[0; 105], "c5f0c52dee7cc56092968e2e476c02ea7d0ec663406e5952debee772"),
        (&[0; 106], "66ad3aac33eea96599e4ea4ebbd2b1e68618169842558348020080d1"),
        (&[0; 107], "0f1250c2746897244ac48c2a8b0106bc2c5a3dd2aa1f8c311a6009d7"),
        (&[0; 108], "8cb69aeb10b281e461ec4ede6cde6f77df3357909fd5b82b7a608509"),
        (&[0; 109], "9497c3b7c8a8eeb701e9ef008922834eb9d771e96efbd3fb4fe26677"),
        (&[0; 110], "4ba07fdf0317ad1ad47a47e6975390e43c390bd432a6db6e84280677"),
        (&[0; 111], "0e70f0238f4c54b6d6a7f7128203a3ff33224c394e21d1123812551d"),
        (&[0; 112], "8407536eeaacbc2e68474ab9d2e0b5c22b59ea08a1ecb216ea0801bc"),
        (&[0; 113], "a1ed744a37ba82882dbe0186d4703846172498f29aa8af77a0c16ea3"),
        (&[0; 114], "cc2e19396ba0e138040cbd69c9d4ab30dda69e5b59913b001ed6fc63"),
        (&[0; 115], "3281dcd6d2bc2ef4ad9555e317656604d6579f670b4fdc334e8d206e"),
        (&[0; 116], "d5a277b44b6648402ac9e0c57720449d5c03bb760af36054c94819c6"),
        (&[0; 117], "7c4c4f2daffcb50652fbf0a237b8086da3c2083962f6042592c52a71"),
        (&[0; 118], "acc7d4e24bf21c761b74078f8a432e9b5ae442a2de6a2170940c6a47"),
        (&[0; 119], "960543ef32825fcc80b4efc341148799cf0d2e4f28cb0a1cd017223f"),
        (&[0; 120], "e047f0f88857183484937bff23750d2c7ff6e89344ad3d101ae3dd3c"),
        (&[0; 121], "94638729d35f26cb0667db24d5eb7a6a87ce1434ff31b09206d6af97"),
        (&[0; 122], "12c38a4c76f140d7aa1e2574b777a8ce07f80da7def343408effe8d8"),
        (&[0; 123], "3dbb23450a2fdccae1f0d6b7d0e9a804193ab95151fc1366947bc617"),
        (&[0; 124], "9f30d480cb366b3559dcf02fa300a486f6354952c4a2ebfee8187abb"),
        (&[0; 125], "91d375e9db9f8cf576811354aa322ab6f6edfbd3a47d09085b6f388f"),
        (&[0; 126], "a82e8c250ff3fa1e8009771b5c31c1fc3de24e2edbed6e0b11ab8e07"),
        (&[0; 127], "e0de7155d81ac8caf412fcedc3a3daea4198d931c27ad83f7200e4af"),
    ];
    impl crate::hash::Test for Blake28 {}
    impl_test!(Blake28, zero_fill, ZERO_FILL, Blake28::default());
}
