use super::{Blake, Hash};

#[rustfmt::skip]
const IV224: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
    0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEF_A4FA4
];

pub struct Blake224(Blake<u32>);

impl Blake224 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, IV224))
    }
}

impl Hash for Blake224 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake224 = Self::new(message);
        blake224.0.padding(0x00);
        blake224.0.compress(14);
        blake224.0.h[0..7]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake224;
    use crate::hash::Test;
    impl Test for Blake224 {}
    #[rustfmt::skip]
    const TEST_CASES: [(&[u8], &str); 128] = [
        (&[0; 0], "7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed"),
        (&[0; 1], "4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5"),
        (&[0; 2], "a2242fce3ca275d9bf0c0cabd0b83bd48633f19bdad07bf4b8eb6d6c"),
        (&[0; 3], "95693216c2530b037db204f1545327842d569551ec396cf5972a13fb"),
        (&[0; 4], "2b1edd09be84816089aa69e1b3cc6d62b7b6ba5c6d1634c25c848406"),
        (&[0; 5], "d89bdffe13d2f8f9e14b2a57bc72c2ad53304b19d07a375f6281ffab"),
        (&[0; 6], "12a4070b8c80c1e4f3da2ee3998f083ebff3f4b1e3cd74b9aa45e616"),
        (&[0; 7], "118926a3058bbe2659afb8744f67cfb02000bbae4a6fdddc079f939c"),
        (&[0; 8], "a8422e29288a070e90bba8e511e48040f607abef1b01cc44c38122fb"),
        (&[0; 9], "7789693ad633743a1bdd7f985777f702ba7c179e6366331142fbfe6e"),
        (&[0; 10], "c83afbf4b9ca933371b469e5b611d4c0d05ca238a87661e0450e5e89"),
        (&[0; 11], "a3a3e875332fdd117a094cad2080b65d949709f966cbd746720dc1ff"),
        (&[0; 12], "bfb75f27010ebabf5cd658a8eec0afaa0d9277c16e167f301fb4e309"),
        (&[0; 13], "db583c58e2f48b2f9cfa1f6e0db451f4c810015e4bfb4dc879e18eb9"),
        (&[0; 14], "87f3b8044faee6f7c3f5b658941b2bc33ae72d712b845812a7f145e1"),
        (&[0; 15], "bd3aa33e6711b4931dbd75649374f5928b52cdf1699573e1b09dff6a"),
        (&[0; 16], "95f45a1ed5f72d645931fec4945761cd5a9ac854786f83f1a0fd912e"),
        (&[0; 17], "07ac8153590d3bb712cd8604125f32358124db8e4d9f5220c7ce753d"),
        (&[0; 18], "b52d91fb1a7f50821ad98f18b229b5acf4ef23fd38b30c6d15ade0b6"),
        (&[0; 19], "f765069c25fd9ae5d5b2ca0bf9280782ee94754206744968f286b01c"),
        (&[0; 20], "490c3163f7566a811402977ba5f288bc39e3f7a7dc5449927f8c756a"),
        (&[0; 21], "5c2a43f5b0235d24ec5a1c60897d80c94818034fdbe6af18239f8cbe"),
        (&[0; 22], "9a44b54a30a92a42a5e9d079d1f5512ce7000cba6210c05022b9f43d"),
        (&[0; 23], "424b9e90671145df930a35b86df92425f109038694e6424de7ba6413"),
        (&[0; 24], "d81f728cde1b53f69d9926617a40be9df2a20e5bfcaa75518041ad51"),
        (&[0; 25], "c5cc056b55a757d919e5d5c2583c56b28b4857d880317b90b4d5eee8"),
        (&[0; 26], "9512f5f523a95442774f96279deda4dc4a5a85816bd2bf2c4311875c"),
        (&[0; 27], "b374acc31fc5999577f20ab57b9e81ead7ef95d5f7c78ebbe6e2b4a2"),
        (&[0; 28], "591f0536ee437742686d269d77f669716cc9eccbd0526048d4466a3e"),
        (&[0; 29], "5008b5613375422f39b4a523366f017d4d0143012b3409b0b598eab5"),
        (&[0; 30], "8f92dd66df9a5f625648f16e1267c733e66ddaad4c958e87d3f48e0d"),
        (&[0; 31], "3fe6d769d15a9e978f2feaa64094dffce9e87477afc2f481ff412149"),
        (&[0; 32], "f44bfaa6938d7d416c4e050163a611b028629a3dcfcfbdf550cc638f"),
        (&[0; 33], "90ba8067665d81749f0bf0724fd746b962d305fd299afea793a0f07a"),
        (&[0; 34], "38567d4b3fc9d13264abf1bb933ffad13b4593d1ba174e88901c0c0a"),
        (&[0; 35], "1cd97e339cda217d35bd42b54706cd438f0fd95dd666fec5c15c77c8"),
        (&[0; 36], "5d96e7fb97ddd9c42b228cc2029b3d501dbe2bcf7c6f9a0007728c9f"),
        (&[0; 37], "b06cd95deeb140c401895c1bb178b6c4619fd4ba70f42dc13fce6052"),
        (&[0; 38], "36dd8514c5937b42b070bbe79e2573826beffd3077ed92f9474b4ef4"),
        (&[0; 39], "afaff364c11b1aa6f2563240e9211ecf3cb98ceea4a0dcc4d585bea3"),
        (&[0; 40], "edd5a4e1fc839121ac8e50e648f33ca29c1fefc13c16855d8619eefa"),
        (&[0; 41], "ca5b443529b98c2783ccccb863926a963397a8e28acf0cc4ff591924"),
        (&[0; 42], "4a93c0cbe59844a8829e17f6de978e6ef7909b5fb5815403718d1d27"),
        (&[0; 43], "46cd05da067ccd73356838605a5108a770cf2fd432f41373d8cee8dc"),
        (&[0; 44], "87f4825bcfb649b25f94c0a90c1315b296c2f79fa13b168f7c6e8642"),
        (&[0; 45], "d9746da4f5aeb14c6897f09a863affa9d5deb8c2c7d0509485acc707"),
        (&[0; 46], "817229bd512a71162d8e1ff0397b17e0c33aede935bae1e7980c5e74"),
        (&[0; 47], "0f4175b67df2cccc87958afcda2198b48f5504333d4b9ddb7d3964de"),
        (&[0; 48], "1abb2405d358952a396b5151055b2cb3ec50bccad907af053e78eff6"),
        (&[0; 49], "380d553b3f3d3bed678f8216f82e4df507b1aba9ef2c5022eb256d7c"),
        (&[0; 50], "33ef842fdad4685e569e6dc2d5d57d98f5c070c1f3fb2de05da009c7"),
        (&[0; 51], "96f9e2516a4d18a4384eeaa89b230971de40cd115d30e681fc1bc24d"),
        (&[0; 52], "b1b921e74d5ab51a984357f5b5f2920425c8730afcb040bdd8d1e14c"),
        (&[0; 53], "6ddba3ca88b36db10df1b934624d48c8ef784ed9f67cb9be2cb9bae8"),
        (&[0; 54], "f30aa929968f4036ac12dd6b9a182728feb18fd06228a957d92cfa7a"),
        (&[0; 55], "502a0663e562d1cda878b9fe86e6c475f7399e12379526be742b1c93"),
        (&[0; 56], "15b58442b1b486ec9ea2305ab597e751cb754ed29f80c336171b061c"),
        (&[0; 57], "c8926e5e61ac8f156d55dbf33791e1ed5262d5132ac1585a15a03d3e"),
        (&[0; 58], "75dca157e2ef6b5cda4ba034e68eb1bb3609b7e862e9805182d65669"),
        (&[0; 59], "7a010a09f8df9198a8c20b0bf7ac73f854d50ede680a5d4ba43259ed"),
        (&[0; 60], "f69afe46c915f46e45879586dbb72adec098b3f4e7f885f3f98ac7f7"),
        (&[0; 61], "999a88f8f7737058f5df0098c509c57da2056401f1dd3061f139f98c"),
        (&[0; 62], "51dc5a03fc1bd0f72e3c5776bfb20959cb831983a08089e667749067"),
        (&[0; 63], "788a80bfb7ae13cb65b7110fc369fb2258ff127d8c1673bc039d4aeb"),
        (&[0; 64], "268ecee2b76b6ff75b8c73e94165d95e23462296f8a28497ec0cad4d"),
        (&[0; 65], "b59929505d87ad6a630558b24f29ab5483041d6658e4de9853de592c"),
        (&[0; 66], "112a5046561700bebfbc9de6ed9d2cd9f2d8cd58be166f3a65cc901c"),
        (&[0; 67], "1991eba2c718b3b0eca7fbf7b1611fd309e12184226e20a48817535c"),
        (&[0; 68], "0abfc09e220e0cf6aabf5f0658748fcdccca6b7a0e7d5fb62e251b13"),
        (&[0; 69], "62efb93add821efea9b12469f3e5eb702397b4347c5219fb688bb975"),
        (&[0; 70], "695b67e2cf1c6a869a196c4f2b4744c7198e850b128605a4ddd4da80"),
        (&[0; 71], "3bcff3ef6d92679be62c2a86a296b8d8c5f7957f4fb8808ffe242918"),
        (&[0; 72], "f5aa00dd1cb847e3140372af7b5c46b4888d82c8c0a917913cfb5d04"),
        (&[0; 73], "9da971dacb4470f1b494bb3fd2b63774e6c7c66cbfb9cfffbc16be09"),
        (&[0; 74], "953ba96fbe53663d51954f3d8460d804815c93a5fb033c229ddb709d"),
        (&[0; 75], "c698f82c08dcec6291a3ab45fcd65d08e42d07e255942c98ed73fbab"),
        (&[0; 76], "40f1dffbbcce5169ddd3689be56b2a6ba72499b8608b547a0c8cd4f8"),
        (&[0; 77], "d442d1f9a5c0c2af4fa922b092a4ee93d1653ff72d5e350eba6b44a1"),
        (&[0; 78], "658a7bcd60607da5abad742305baf8fd8154a15b4a044077d6b04ec9"),
        (&[0; 79], "dd4104823574436d9eb6481097cfb50d4c4efd097aac4e0204834a23"),
        (&[0; 80], "0d4081ca7d9f6189fae1120a7d42a9b227ebbf398502421aab8c660e"),
        (&[0; 81], "467a39bc78ffe8047242dabb9c270cb233cb3f893f6d6ccf1d2994cb"),
        (&[0; 82], "c0327fe0b0be43ac4a0e2fba4848c94cfa304fca9d9e0205a311ee8f"),
        (&[0; 83], "4585e0a7e787006f7248994b636b88ef42641319254e5685b1a536b1"),
        (&[0; 84], "3ca1d3ea7f699e0af0f5a4da6fc177fceac074d9f486c4e97b124f58"),
        (&[0; 85], "0367be22119543a6a4548ee9951c16f30fac5b9fb981a5d46ee75202"),
        (&[0; 86], "f16cc228c6b2ff6424669700bdaf027169eea095d5c115eec0786b94"),
        (&[0; 87], "49672d612bfdd08e54e9c9038d0f74977ff5e9239e5e34fc3490986f"),
        (&[0; 88], "443c7c58beedd6ff2597717314650d64036e69fd8b032fe0a966477d"),
        (&[0; 89], "a3d92c8d8de0466b57861b06421b71982a0b4d1d12ee819122c100ee"),
        (&[0; 90], "08fd4305d4cfd2e4285b362c4e8acc6f821296b903e417064b906013"),
        (&[0; 91], "67da787865b174d8962fa6a126f08b4081d9ebbfd6ee5cc0ca52b1fd"),
        (&[0; 92], "26260b34d8b5db064c57fc89e1689a087ef10ce6457109a66ea2d988"),
        (&[0; 93], "8ef4c8e60b9e96a9ebafb2678d6297d35ba883b2618d4cf903a8e8b6"),
        (&[0; 94], "3dd321c6e2483aae6a96ab75caed990fd093baf2e2b63f9357631133"),
        (&[0; 95], "c9c40cc1c661cfaef6e19e786a61650892c82f4075e20b9bee7e0881"),
        (&[0; 96], "bfb410209280e65504c8e9ffdd25e703e90dbee7135bdda451a28ab6"),
        (&[0; 97], "9442e46703a12587bf7e653fe013306ea99f11d3fc6110e375802eb7"),
        (&[0; 98], "774c3ac148bc789eac42ca7e3c49d080ac30cf1ece59840ccd9c746e"),
        (&[0; 99], "acf72fc196b634c9d09fedad9357a7ce928710f4f773a4d89d030ce0"),
        (&[0; 100], "73c83880896c5a42d02aa3f5b812edfe6c7f32c85861a56526dedf62"),
        (&[0; 101], "216547743ffbcba420e2b7e1de778417df947de76acf798f8dbf3c80"),
        (&[0; 102], "1e4cd7b9184b2804d5a0bc040b96b54ed575a54b56b8ba8f665d2559"),
        (&[0; 103], "cd4109576ddd06e1fc7241ebdf6eb47197e1140b934cc819362916de"),
        (&[0; 104], "8ec17c5391a4641a13f063fe4c2aa9312e6116b17986030f21f35a53"),
        (&[0; 105], "e11c9e162eed7c7a21aef03a6877648d226564428421f0a190cf20dc"),
        (&[0; 106], "f48291e1ed4e67af007e0b25399c2064168b97c67552650a567a42db"),
        (&[0; 107], "0b9a00c4a903673d1c10ea997f078e16868af6effe693fb267e51fb2"),
        (&[0; 108], "1454bac68f8c0b121be640de7a389b11dc35a4288c9feda4d2014718"),
        (&[0; 109], "f802e3c54ae4efa75892c903fe502a5a79cf6d179a303aab201bb5d6"),
        (&[0; 110], "2abe8578ca023fb16b8ecdad210294199867124550dd4093a0cfc4a3"),
        (&[0; 111], "06022126c58995d67fdfa2c9f3c4c13f660eb641d4a71e7083303432"),
        (&[0; 112], "9fce65d6f432e145503c175c97bb1fb238d91999ae8b6e7c8b5bd216"),
        (&[0; 113], "727482bb4dfbf23a4987f120ab63e24c5eb5ffdb9edebe5fc6ac8e81"),
        (&[0; 114], "413f4864fbce999dffe8cfd76b4f6a652e61f6741420a6ab649947eb"),
        (&[0; 115], "f94da49da9081f3835ffe4d4e588625d29dbda182d9b82316fd5e81d"),
        (&[0; 116], "09ca16716cfc0a105b62f92b397f81a0a505c3f30a9b9a569b0402ff"),
        (&[0; 117], "4d9b98176007e0d0fd5c38d59776db2ca338f5810f2531c212a5e4c8"),
        (&[0; 118], "06d75d0fbbed3ff136acfd05986e98efaf18124073e87309b3f9ff93"),
        (&[0; 119], "0ca3b92ba941c60ae59d50a8ec79df70712ad7423eaf7630bf2c44d2"),
        (&[0; 120], "286aa9b64d1cf6cd72a34bf02939311802b5139ae842a6d81d52ea10"),
        (&[0; 121], "f87971e52abe42bb5c23d95c00182c3a06a2f7f237f081557c153045"),
        (&[0; 122], "5a8dccaeee78aded5d6061eb0af5f5ef33a36457bc393999da7024dc"),
        (&[0; 123], "ed70dfee00fb7008f973fd9466d80d9072303257ef1ac52fd75a4a3a"),
        (&[0; 124], "2943f7745e67742ecc00ebf9693f49bde74cfbcc75282f6fa6e0d934"),
        (&[0; 125], "4d986a7ab1ddc2bbbfef26d8ac2a904e7a2aa75ef06f83e794c0686c"),
        (&[0; 126], "5a4ec09be509439ecf5b90adcce2211b7dd38cbf64d9cb34718dc588"),
        (&[0; 127], "05965d871df38e4a66968dfa4632a9c5fe93a3f31007500f6f1c063a"),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake224::compare_upperhex(m, e);
        }
    }
}
