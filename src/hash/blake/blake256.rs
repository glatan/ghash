use super::{Blake, Hash};

#[rustfmt::skip]
const IV256: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];

pub struct Blake256(Blake<u32>);

impl Blake256 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, IV256))
    }
}

impl Hash for Blake256 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake256 = Self::new(message);
        blake256.0.padding(0x01);
        blake256.0.compress(14);
        blake256
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake256;
    use crate::hash::Test;
    impl Test for Blake256 {}
    #[rustfmt::skip]
    const TEST_CASES: [(&[u8], &str); 128] = [
        (&[0; 0], "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"),
        (&[0; 1], "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87"),
        (&[0; 2], "8d3151c61f549a6b58740b6a1c47fe8b92432f1993c1fcc32c062b22719d109b"),
        (&[0; 3], "94e096fa68a4213a795ebd3db47c7afb18fa5f4396cc9949e654673d0a9f4c5f"),
        (&[0; 4], "c53786013b3d5e3ca82a9e520b7be9128a63e95f2245ab6168d14d2e267750ec"),
        (&[0; 5], "5fad9c89523328332b4a1c7e38af90cd522bdfcd2f025b3f467db309d6824b4d"),
        (&[0; 6], "f2eda28b8f96b327ead5bd902386c0dfded351d19cb0ec56a5753c2038ea76df"),
        (&[0; 7], "a9f8bbfa40ea22e82a8514e4e01b92f73f87ed47ff8d16c2dc226bb354a71481"),
        (&[0; 8], "9f6083b1d9a623fc623e430b50f267cb4f79db2240944f588f72bab06dfa116c"),
        (&[0; 9], "8ea5a98fbce4ca40d3c2df713609079ea8dd0b06ad13e33fded4ac610343ed4f"),
        (&[0; 10], "a2b2a471af36cd8a46fc8c74b407710c2101a69207c3a543d32043bee1b01090"),
        (&[0; 11], "4a02cf40cece48219c138a86d6f5e9fb3b955027410d745e9917034aed73e10d"),
        (&[0; 12], "8a1b093ddd29e1a2358e0b6e5099dd405bd785695c71d649ead1c5e2d256da52"),
        (&[0; 13], "11476e9b0b613cb4c0579bfecc948f02861ae99eeffb44cae038ae00e8b78837"),
        (&[0; 14], "d24f382a2ecbc45d1255277193e78a926dcdc208fc1fe2710804ec50340979ad"),
        (&[0; 15], "75ba7f99fa4637ed90347e0fdfe46fa4b407394d8609586929525f4c43821498"),
        (&[0; 16], "efb0ff4ae7e722a51b480fe17387824618e3502de17f215271c5d009b377c1f9"),
        (&[0; 17], "5e495dcdd465742d3188a2260224e36f7e082475fe3594c770c3be97f88e8704"),
        (&[0; 18], "7fc31b126775c54ba48cc7ba0086b34b61eaa8139ccd1625c462c6d00888bb2c"),
        (&[0; 19], "d6f08b5fa2c615b7af0d05607f022daca9217235bb10feda0bc54c7c16d642ec"),
        (&[0; 20], "e43ccca63840614c57f990f81e8668829c89b9f976ec6eb6b2de1b56c35361d0"),
        (&[0; 21], "3e390419c8fa117e37a069bb3e9f48f1597b66beda9a4d5683076d5005c8a1ad"),
        (&[0; 22], "cc5a4f8060fcc7d74a0941da7ff6da6850be781a7575d77fd8f9618dd837b4d9"),
        (&[0; 23], "f556af690f75c8955fd1fcbc35097bc868df50076efbfe5a377679db9c0c2382"),
        (&[0; 24], "93b3bf09abcc3436ef3ee085157587a43e1b2b31a61541b811c4ccb1c93d856d"),
        (&[0; 25], "7ffc7941b800912edc39e68c30d5031afdaeb0128a79bfb162126e866ae0599c"),
        (&[0; 26], "fa5b85ffcf21fb20dd3d679e31bcaf742879b73d6f93cefaf92fc36f9f57b304"),
        (&[0; 27], "270e111b76200a1d97a3113ba2216fb2e2a481819a8ff7987cfabcba7ceda0a0"),
        (&[0; 28], "ffd13436c6f146c9a35d27be905f9d32b336e7822224921ac5b3f6276727876a"),
        (&[0; 29], "97b09cc02c21b7b517ac16deb5b8c20dc97bb9f58e738f9e3e882bab58f296f5"),
        (&[0; 30], "6063013e3117288799c315f13b7edae31a6ba85474dca05bea15e3ed31c584d8"),
        (&[0; 31], "6369113db350b89a355a643a5b5917c4c73d445e09eeb2a5fbe4bdef9c359bfe"),
        (&[0; 32], "05f6ac47accd338d329cc16f6d59f3409cc8bfe76a272e1eec612e49c115145d"),
        (&[0; 33], "bffed141c024c6bf3d22c3c252d95a6b10ea117841a71f1caa30b29dad3bd025"),
        (&[0; 34], "a3b94dd1882cf2c6d9125dc19d5059442709dd6b083235c6bce60a3b0d3b6c67"),
        (&[0; 35], "ad943fc8801c2269fbe586cf10b4325fac07a433c3400d18b87e5dea34ddf2b9"),
        (&[0; 36], "e12d5ecb16b5b0092dd0b0425865ff4fded956614914f5f9a7291be6e77e6c52"),
        (&[0; 37], "9a19594b5e8542e5fafeb981b5f897770372b8586be8d12e6fc87faecfc9673b"),
        (&[0; 38], "99ec630ac5787c7614bb435b53cccbad97fd779f7c1bdc5632a66d73bf51c024"),
        (&[0; 39], "53bf88ad6d353f3376759f7e18e58e540eeeca395ff654d2d9443a13511accee"),
        (&[0; 40], "776484204c66ec4894d5a3879aeddb3772cac5fc2795ed26d9ef2c68f73764cc"),
        (&[0; 41], "34506dd069c44640b938b1f618d24215c303dd87295d28ae8cc1ffac9eb93ed3"),
        (&[0; 42], "000ec7ce1557957f336fca7fcf111d4c46cac2280b36f71d9ae45df8fb04fdc8"),
        (&[0; 43], "3d9e134cd9d202d7708be01d95defdd37864aaa5e3b86a79f644560c4026f41a"),
        (&[0; 44], "8816a86533fce5760b95108887001a1064db496c94ddfcbb260b4813ab324d8b"),
        (&[0; 45], "9095c7afe9c6d99a256529e009e72c4095350914da622f1b9e3a0f126c05a03c"),
        (&[0; 46], "27da8d108b3d9f8f2915e4b8a4929964d95ad44a4af08f755a71cef6a088f0d8"),
        (&[0; 47], "976b938f400639905787c38b15ccabbf35f098a8101c682969a2801425d52386"),
        (&[0; 48], "a09a275ca337a23ac8ec5e2bd348b93a7fe5344827ffd72b2835a93120d2fe1b"),
        (&[0; 49], "1e947a837bff8a4b3763a38125f16ead2de60876d44e9f03b7c568ae9221053b"),
        (&[0; 50], "dff2c9686cc5d67b04e7ea8a409a868d5607f9a32fd2811eaef1118d21464691"),
        (&[0; 51], "eca06b3d868bf78a012c1bde5714288eaaeed3f835644365dfcc80439fefec51"),
        (&[0; 52], "4cfc5c97e69735e43761b8d38a736ce4d269da7c979f01f322d02182052539f0"),
        (&[0; 53], "de9c1708ce00e0322143851043d6c6ebc5b9445cd8d27d3bb48ce8b35374db4e"),
        (&[0; 54], "8b7b134b0450f2ee19935dc82df3e4fa7f990b320b1a9afbf1e40914c6fb67cc"),
        (&[0; 55], "dc980544f4181cc43505318e317cdfd4334dab81ae035a28818308867ce23060"),
        (&[0; 56], "26ae7c289ebb79c9f3af2285023ab1037a9a6db63f0d6b6c6bbd199ab1627508"),
        (&[0; 57], "363446fac666e859deae9e81c458662371b6fdd0793712735911071c2be9456b"),
        (&[0; 58], "da9f566fd7649b0e4e831edcab63e38a35e337c216a02c299b22478fc7de36a9"),
        (&[0; 59], "0420dcee3d14fb6f7678b76e5481de5b8c2fa48493503ed6aa03ac0986c2cba0"),
        (&[0; 60], "91c8ecc78b83502dc76a7bb446384d2ff4970eac48ac8be4fce8b2e46ef235ee"),
        (&[0; 61], "ce160ce4a0f4e1b8fef3349ae5747f8a49f431c42f853a177c11ae8af9ee7b33"),
        (&[0; 62], "dcd8b68b9685b69737359a3a27fe31acb3230009a1a1d691bca01351072033f9"),
        (&[0; 63], "254b522be8c966d8a2c44a2bffce8469f8223ea3371e14e6387d60fc790361f1"),
        (&[0; 64], "6d994042954f8dc5633626cd50b2bc66d733a313d67fd9702c5a8149a8028c98"),
        (&[0; 65], "081e5d10c8f46e140db4587366c4718462709d000419c1b00ca05a5763cab5cc"),
        (&[0; 66], "891ac77f8e8d3d3fd6fb2d5e1bab10d60c41ac934377a6e27a695b6fb97759fe"),
        (&[0; 67], "fdf4808a1f4f392fe7ed1a808c24e0e3ca9e4b739d5a38ac606f76a09ecb1887"),
        (&[0; 68], "5df4579fb9b15f43ebdcf3ece298466fa62ca62eb4e59ffc194a4a8d797ff60a"),
        (&[0; 69], "51a08a1969fe2240dfe88415957d35878beeb6c4d9181d1df3bc1db53b2c6b0e"),
        (&[0; 70], "d57b6cddb431c9bd4da5c65ad1b5c313cb849e65443c4c522ff215040ea4d8d6"),
        (&[0; 71], "692f122cc8b728fa86eac5f16995c57a036ee9eb7c3804d6ca3b3732b936f4d3"),
        (&[0; 72], "d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41"),
        (&[0; 73], "945146d19392bf879e1d2a35b14dfc0288177a1befe2ecd0b5c5ed02f692f057"),
        (&[0; 74], "519af6dc4fa91ae7ccac6be2e35f6de57ad1ce9bb8e30fed26b7c1b9d94168a7"),
        (&[0; 75], "d7f637c032ec8def05164358fb27b3cfc792883ea8bf0bc827a4dd090211f347"),
        (&[0; 76], "7efdf5cf5ad819cd1c415b7cfd1a6a9db75def075d9c26aa0df58855169498f5"),
        (&[0; 77], "db9b8ba424ca1fbb9d425632f33b43dbfefb6c91568d65877451769786c50ca1"),
        (&[0; 78], "b67a4fe420e575ac06816123c8c3bb88a24f5ce4a9c45da7bc5a6db7ca7153b0"),
        (&[0; 79], "4f2b66738e050f254564b13f9ef430419640ae1d7c92267eb50eef87261a3c09"),
        (&[0; 80], "0c7b159452328517463db487df5e39b71322afaf14ed562ce9d18d7d9051b305"),
        (&[0; 81], "409dc1c72d3a0dffa3d5e00a42770090b27f9b6c4f3e681781962b189dab838c"),
        (&[0; 82], "5922da284a24d3a632adff5ede9122b9a7400a11245b2625b1af6a5c97ab42b6"),
        (&[0; 83], "ded12cacb42b7e4730a906f1e1201221c507d2b6c3c4b30feb4ebac5bd5d4c3e"),
        (&[0; 84], "799502a46e68ecd1f67c2a0039eb8769dd96d48704fbac52af29f5e84e493259"),
        (&[0; 85], "54b5f38038c5ba948ba3882d8277b1220eab388022b1f2b16fa2d885be3a309d"),
        (&[0; 86], "03209c7f20cfe3e9a2d3f22b6d4e6aadc393717a493cf4832a5ebd08de512d26"),
        (&[0; 87], "1c497fe3e9505149d68e1e47cb0762628212989672ada7aab2aa8707b8eb9d34"),
        (&[0; 88], "d023c0dd0826943978890c6c6bc1c1ce3c4fbf488a584c16f7510820b2074a5d"),
        (&[0; 89], "6bd635103f36b84d2b70cf029c5c51369b8ccfb6d841bac8571e999225419f8a"),
        (&[0; 90], "b56b62a4ec59460cce1913254c2b0e2e34f6c0564b1d18b46db72bb3e5618a97"),
        (&[0; 91], "acf0d1ca0f042dc4da31ee11b0e165ea459f1a3b4ef41acc034ac0ff801477a7"),
        (&[0; 92], "00b3312413d12cb5c0aa604a5ed8b2c99ab0368951ac406611d77de566eb8876"),
        (&[0; 93], "b259c15e2beff7c8647447bbb9af5f5c8be4c25ca5af732c878c8889dd88f7ac"),
        (&[0; 94], "2e7520c5f2cf605d886e2fbdd4eee84b0794414874c0f15322b8ff54f6e10bf9"),
        (&[0; 95], "19bacdc971ad53dfe6a684abf5fa98566ce16993625917c424899c68a8d98c19"),
        (&[0; 96], "c8aef8b1be855a8ae29d319d30072f49d3389eb5d885e6b5e9fe183879897b88"),
        (&[0; 97], "a2df5ca104e744c88dddc28e78394bac3633ee67ab471d8cd228f8b16677be76"),
        (&[0; 98], "6a7898208e1e32cf20af9f4ea61aa6a8d75c4d5aa6ddcb45685e952c72ae1e1a"),
        (&[0; 99], "b54bfb220bd1b95d71c9f0d06300363166bd18328f2fe5b366beeae9559a0445"),
        (&[0; 100], "db10fa7d8a13c4bb74729474485366132da7e221ec651f57a3b7fc3258af9696"),
        (&[0; 101], "334b97ef5238a146e9235904ac265499fc0d20076221b1ea7db8a6fd624acdf7"),
        (&[0; 102], "ebae16aef748c2082b79553734be100f7478d224c0177f3c62360ff075dd395e"),
        (&[0; 103], "b3cb5422e31f955c1f21b7edadaabd2385296956f40698dce9a2cdd68b0119cd"),
        (&[0; 104], "f30819469ab5f9358a639786def38151709024a0702020c9216a8fcc06433485"),
        (&[0; 105], "881f3b93ce0fde1a577526c0fced01ba5b1706a3b984110d908d1ad5ec2d455e"),
        (&[0; 106], "352e381030dad85646c492dba0ec7b94a527677a8f4e3937ec4739eac378e611"),
        (&[0; 107], "0cf2db85bffc400372ef7958b5d17aa9cecd22f8e343106c701d6ef040eab91c"),
        (&[0; 108], "6dd7cb07cbd05fc1e10522464ecbae781e3e4a21e24d684339609c59baf70d1f"),
        (&[0; 109], "13ce99e6df0ff68d6d8994e1fd09e8589eaaeb36f9cd91c97a027eb1bc814437"),
        (&[0; 110], "a7fdfb4d0507b7eb05fc8d32644b94e225d50c3f26f6953a740e467e39987977"),
        (&[0; 111], "240249130fc50e31828c34885a8d4549be4df64ec83d6d288142b45ad17e29d1"),
        (&[0; 112], "a80edd4667861bad1d84a58fb1e3577cdaf5a4cae2bedab8184db0e2928babf9"),
        (&[0; 113], "5b535744aa7b5ac815ae7aebd4edf3d2830be564bc6f00a57a70b3e230951fa4"),
        (&[0; 114], "a8717dd1ef1a6bdc5ff262afb722d6ec3a3e37070409cae468476959f8cb8e95"),
        (&[0; 115], "0a7f5380a0e34a03d6bf6fd11ef6948ed03ec2105bac535890e0c44711fd2427"),
        (&[0; 116], "b5146e894e5d4a10f4cdd03dbb6032aa97b28404d11d7654dd8cfc84943b4869"),
        (&[0; 117], "74b34a31140f6e6a896fdb6862fce14fa53e4c61852b9b61a8bbe3e7828cc0d3"),
        (&[0; 118], "3172db4179e980448f3ebdefbc8444feef71f87cd7a83e44c48dda0951637528"),
        (&[0; 119], "62485b9374ed4f0a788a49ad6e6498173678ad2d4d4d2748539ad42921375ef3"),
        (&[0; 120], "a48187b6556da878712df64af27acc800b0e0c492c9f82cd9ecf9354acfac0d7"),
        (&[0; 121], "022aae61da2208d34bfb2dedb705d748406616b36542df6d77916ac4fe583a6f"),
        (&[0; 122], "ac4a7605634abf24c13eba4accd12b29b4e2ca43cd5020f434e3968bb03aed65"),
        (&[0; 123], "a4ad43a0dce6d28383165b0df7126186721e41fa586c0ab6682b2ce6f4c730b9"),
        (&[0; 124], "024fb809b57755f8cf3fbde4134d6bae10bd896812db095d27ccc16222e7e242"),
        (&[0; 125], "eb0e18b460fbfa8b4c30be041c5563aa5a75be5529b24195275da5db8d1d415c"),
        (&[0; 126], "48b40953412575afae9c459bb0ba50166aa087449a22ead59e6c0744ca58dae2"),
        (&[0; 127], "1bc62e98b1dda071c0afbd31140743a291e3f79510c53d35dee928b0cec00fb8"),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake256::compare_upperhex(m, e);
        }
    }
}
