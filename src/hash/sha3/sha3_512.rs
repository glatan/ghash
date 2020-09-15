// https://keccak.team/keccak_specs_summary.html
// SHA3-512: [r=576, c=1024, d(suffix)=0x06]

use crate::hash::keccak::Keccak;
use crate::hash::Hash;

pub struct Sha3_512(Keccak);

impl Sha3_512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self(Keccak::new(576, 1024, 512))
    }
}

impl Hash for Sha3_512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x06);
        self.0.keccak()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha3_512;
    use crate::impl_test;

    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); (576 / 8) * 2] = [
        // Generated by using XKCP(https://github.com/XKCP/XKCP)
        (&[0; 0], "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        (&[0; 1], "7127aab211f82a18d06cf7578ff49d5089017944139aa60d8bee057811a15fb55a53887600a3eceba004de51105139f32506fe5b53e1913bfa6b32e716fe97da"),
        (&[0; 2], "71cb4a0b4d323a3d9d6f8188db4d3266a298053c660a5152afebd0782d07820d7af7e4b1f327e150753fd5cc84b3cf949f33f7a64d62cd764c154f3eec100f7d"),
        (&[0; 3], "0a7b1406be477b9b994a976a49a236ddf177ea65d04e770264b32c240eb229603f05b573772d406fbb321b8a80f90e73a8eac5182e2dacb1e93b37c9ae380c37"),
        (&[0; 4], "82bb78accced463db810e506218ad1ce4d702491a4921d55075985badb2cf73c1f9d9035ca83cf383505dcbea17542943ecdc9e4c476d1c0a97c891af6f2772b"),
        (&[0; 5], "bda962340f636e37e98903953944cfe22d8f1ef6b564e5bea44a575f2500648f35e286f7a6dbbb26e52246151a6cd055ed7370173a2927a9683f25143844ffa8"),
        (&[0; 6], "68782e54497296a64b14987023a61f96b741b1f2f7ff6095552569a2252783c85c99e9fa43273a196ffa0ff72697c3449682175c6272b8586def3ced6e701b37"),
        (&[0; 7], "0a28b1eeba45e166119ce95b6cf76b24946ba8dadaa4b7c10aff72272bfef3af1408ed34f1aae2c8f65edfc29f0ca8997a9dc9c6953484a0f2de1a35e0278168"),
        (&[0; 8], "0ade1db9cc8552ed5997a5642d835ebd191367d08c24564a735a16f777ec7a0f02e7575e5c778e39d6cdfa79006cd96bc4b40967abbc23b9109eed2f296af8f6"),
        (&[0; 9], "259ced9d6af7a7d157938a10d617e480b1e5d498d8b1aa6f854a90ac4639917e4fc03dcf05ea49fc2b50cab81f32c4d6b38396ff7975f22342f0050e88870f3a"),
        (&[0; 10], "e12f775adfb4e440b74af7b670849a44b7efd1612a97a3a201080cb31944f1f2d9f0eae6b7c0cdb602f6ff0ba181add9997fd06e43f992df577aa52153ca0d27"),
        (&[0; 11], "b8b697048ecceb141a7ad801a21a9459c2db367d7a3699401bac77dc3736b3dbb536e610e925c98ba0da960256160b050a88c7fe08b99a8ec6878f6d3a907c54"),
        (&[0; 12], "39d2b18f0b2342ea6c18cd54f6c5c99b3fe36b70cd9f48c0f9474b24168a49a889deacee025aa2909ae8f53139de61a4d4ba16a6c97c682b066f5744a0820ff6"),
        (&[0; 13], "560df89e24a0b9444ba11fb54a98191682e2db09d77a222d5a90e978e14c14728b98231448425b9e36457d6a9edbd6d8b083cb0a40dc567541a57fd3a4afd2ba"),
        (&[0; 14], "0e09770825fe3aec46bd1fecd11b7888e0ccf7d6c438f07543c9e4d359ca353f77ae3ecc8291fcbc3151055266c05dfd0a9bb0eadda8849e827c02ed995cd861"),
        (&[0; 15], "7482b4b9146c203f176ddd7586d7607d6a44687c15987b37051982ec53fd350bd1e3ca6c8bfd8fbbb4e3f5cf5de5815cd1848bbb9746c091d4870a837c9eccdf"),
        (&[0; 16], "f0140e314ee38d4472393680e7a72a81abb36b134b467d90ea943b7aa1ea03bf2323bc1a2df91f7230a225952e162f6629cf435e53404e9cdd727a2d94e4f909"),
        (&[0; 17], "8e5077797fb39431b3abd4296813ed1d01efd08a3d76fd26774bec08f006904dbee89675aa40d92fdc83b459015881e294fc25b9fc7526c8d1ebdd8a4bcd90bc"),
        (&[0; 18], "34c8a786356d7113df07bf776cd34103722dc9e72033355f52f0cca018942f4f7f2cfa6eb933d397c9be80aa7c06468768193e8bfbd42637788a6269ebc0537d"),
        (&[0; 19], "9d6011f46258958e42c5edecea652b71e35137f3d9d467d1a1f46fe42ad20496de3d937f8be0f3e202714bac9f8e7c751ab08e088b83485e33fb511c237e7ae3"),
        (&[0; 20], "7d795fe6a97761d89b35f64e09555951f6ec2a669a9fa03481c100ae158f183e2171e142437d2c3a42352108a22a7e3d797beaf6c3075db419b6f4acca479c83"),
        (&[0; 21], "fd3d300d34e74e666d8af9092768cd5cdd801af9b05dfcd4f1b7c71bbe0f0cf2648babda613ce2e115b97eacb6040653c56c855d4ed5991c60edfb89d5353b52"),
        (&[0; 22], "e5da4241bddb144a2b03f523e1eb14796da91749e264c41a4bcd28816fbcd92988f8547c71b3630aa5c4fb517eb2303102bc137cfe6671784bad23449ceb3203"),
        (&[0; 23], "a3bd1950b38e9919d714ad9e29064dcbe0f8334e305f317b5c66bb93393a8f3a30298222a2f7c6046a7677980db9d5ce61d8b2e65437ff9e2c61750bc89c0314"),
        (&[0; 24], "b06923bd6534c6d4d435dcfa7593c4887213af25cdc9c3f8e854831af2755e3b229a1f64ed6acaa471e84850d45beb43e46e3aac284e7401c8da98ec41809aaf"),
        (&[0; 25], "050596c7cf737af437c007b658619cacadc988450fb62af4b08784e8aa97add8b1feb38c348e8d0f3781441d709eab8980beea084c584a2a3a2ea2204fb12a4c"),
        (&[0; 26], "1031d4f3514ad382d23862a87e205c279ad8aa71dec17637de85db305492fc298d39a248a4932ec5a9e6889024a5d53c8c8e5aaa9bd146bf53cef4178a71f1a7"),
        (&[0; 27], "f5d4eb04f41459ffff2f351bdb3937cc0fb8c15ee5bb7e7ebd0f0b529e9186e9adb248b10b26198be4a0c03c6220bb2da642cdd1fd13a72315b79724d45a352d"),
        (&[0; 28], "3d2971ad8b24391246af4b2a8d6dff82d560d44ff32c1251745d60d11e755e1a8fb85c839ca2f77ef12e624233fa6b4f3ab33d2c3f427e57cdda35c960e25177"),
        (&[0; 29], "32311df892b57810055bbb4aa59d2667c86bbef1e32421653a935ad96ce98d657a5ecb86512d964bdd3f810b6902b1a215332c849fa22be0ce0308e0cd4afc3c"),
        (&[0; 30], "25cd16f5dcaeb03539a11815571cf7e032a030bd597efa8a5d8090c4d02f96ccb32e3600291eda91034722b103e2c5da95cbfbd7d146039bd0edb5672870a425"),
        (&[0; 31], "61599c6bc5f657b4a6131a624b2465ec5062912d2cdac06264b0a0b0f0cc2184a225ae000b80f4c390089b2538ee50300b4c8f5a742799db10f4a6d1fbdb25ad"),
        (&[0; 32], "ad56c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18da57bbdfdaaa0fc189c66c8d853248b6b118844d53f7d0ba11de0f3bfaf4cdd9b3f"),
        (&[0; 33], "8d94b4a10495ff5f98df8ceb6df0eb393234d2d2ea83be500924bfa91c2d660cd0166b52c96d43d322f022e4645effc79a5c7c6a3697c408c1106fd1075fe54f"),
        (&[0; 34], "4b3bb1565e8458e97d3101c5116eaaf47415a1fa601a0eab3517a50cc94eb9cd68ce6b55ccf425dc2e6572134a8b090b7c75dae16ed74a348b4cd8e77170672f"),
        (&[0; 35], "1b3b125d56842c22c6a8e805ab049fd4b28e752b9a897d6c4dbbe6a6796e2b9c708710ee30d09cf67536a57e7cf94c6f92908eff193d3e0372a1b152002b9fa4"),
        (&[0; 36], "ffe048ff74e2db3d82723fb82de7219921339657d31e0509da6ea9506fb167c463bcb46f90634b51687caacfdd3e7d36eb21aaf599062dca8f85bdcbb26c1cec"),
        (&[0; 37], "7f1f6f74d04897af32ed4c858926bd45d05f3ac0c17995d046ae76837ab20116a0fb8a1d9ff260db8e420a9605a9b0fdae53bb8894da4ddd8e57bb634860cfb9"),
        (&[0; 38], "5217a6c342240b89afe0f8ce41308c98e526157e39f3880033317004bb9fce09828767d0dd910d8277e42c3dd99be14ede30dcff359800a16df8c5df896f63e0"),
        (&[0; 39], "4e53da197543b710239a47279b2579629450b8a3c4614f82d0875dab2c0877a6ea45c81ff65b86ed632f01156f34f83bd9fd7f89de587c6d90c5088393f0d19a"),
        (&[0; 40], "2bbe3d239494f6c0f5c6acb50c3a3b4c77cb764b4428b5b7e21b69d51dd1a860eb7462b9c0612f8ecea8c35ef7f4303c5be656eaf4257125ad1d6b4616354a56"),
        (&[0; 41], "d6a3b2d4c44b4d62f8921ee83553c8738c1084bd7baa2dda870beb821ef1ff96a156a7bc3f06201cc0f4a4467078baf104cf2d2ee5a839a3322918a3f70191e3"),
        (&[0; 42], "aa6f5d47ed194dd014c7b2f4754e3c69baf081774cfe640ce2163af3882ff23febee10dd4dae4539f62f9a4274de78b908df55efd54197e3d81410bbec92122e"),
        (&[0; 43], "4bdba0b7027bdcea72e9f7f1446348660d2957173ea14b742317911b209c23bfa480f02040c01682e8c65bf174867b8f0d4d14464670e89eb995cb9504ffa17b"),
        (&[0; 44], "500fc170a4e2beb78df8d7366f28415706df533e2af87e4905be5056aaf5132b19c64c5d3031980fd41f097bcc0eefdf07ea7acd4b95e7436df04069a1bfc3f1"),
        (&[0; 45], "38f653d8fbdf4302cda1b0bff05488f4195c6d9ebcaada3315cf79640f53368755e5b17f438c6b0e2105d3a2803f4c4bf264491dfac774783334ade5e07abf50"),
        (&[0; 46], "5321113f1db0c2ea4f619c8419809883ae0cf8e6d921335e53f3edc021679d1268128e99f306879457b932bb6883a0372aca189ee80361b530e3ffda11e8fc0f"),
        (&[0; 47], "eda12121229ba88fbd8f64af0f6652df5d484cdc236a464ff5ee02bf9d894b46566b5ea28cc833f779b47b641e375a6ecedb86269ce2a33247b6d2f304846f6b"),
        (&[0; 48], "ab9761b6c372a0c2b69d98ec1a1091888891817e99742a910bdb86867e664325c7e66ae49bb31daba261dcf0eb18d258fd586b1431fcdaa592e598b5299f01c0"),
        (&[0; 49], "e46224610289e99d4762e21effb4e39cd14d2bf6f4a1029a8e116c3f9770c58875f1cd7af7808d262c28888f5bba818ec9c66a39dfb9282e05f419fb5d6f2adb"),
        (&[0; 50], "189232076457fc6c5d9236bb5892cc3900039e357ca7b4987da89b09d617aba9c9bb49d2f3cfcd2ced3cb1639e98bf76fdbdb20f6eca94233f10730709234924"),
        (&[0; 51], "62f162ceaa95da62e692a360d9aed905805971bde3865be5d33546a3315ccbcbfedd82aa1a62a18b40b186e54b114467991183b33542618ecfe8c1f20a5b5a90"),
        (&[0; 52], "6ef1ad2aa2317736f67b38a02ddbf91f155d8372d1bb80638b54b0605960f05b2dd62433634e63122788832422bc8256be88b12f3dfccd06e146bcc9c94da57a"),
        (&[0; 53], "3d802d050bde13eaeae2e5d08871f6de494292581dbec0163230c623d8b54fccad87cc73e9dc107c75ded2772136577d75f1e3e9ffb0a7d9e6f59012d2c47387"),
        (&[0; 54], "6d527ee2f8d03c8aa17fbddfa9903f4c60ae6938b816d2eb37a943aa3fde2473856bd9dbc1d55f38d20a05256a092274f8d4318a5d30d0809202f52457556b0a"),
        (&[0; 55], "c6fd5eac307ec95189671ea599d7cb67f839e837b2b211e09d8d5aa60dd319e2026f7d3005f9faf4782732e8aca0f3639cdf92cec8259f605cfa3f609bb955db"),
        (&[0; 56], "7783c7978ef6a4858997233ccf0b980794ffcc550e9d8913a7226e5d5f4d44c9c1116af303aa92bbe81a71ab75a9b498da48981952f3b51f504b015650bd2d4f"),
        (&[0; 57], "8cd6fb668b47f1aa88fae1ed17db54e015f0e22271b1c721fb14f2f5c58cc5e16c5e62b68c3dfe05adf05a4d97a7fdc15db99664906cdcc25dd5183dcd1d3301"),
        (&[0; 58], "47658ac3cc7243935deab9fda3f87f1202514dd2dd05c2bcd943140588192849b3a64a9e3b5ea3e3621b08505f707406c9e8b15e5bff44c1f37f09e127a0604e"),
        (&[0; 59], "e17530a0b557b0fd1431e5ce6788116d1b472f3795791a0db500e417e44bd5f6fc6b3b4922337bc317cc974c5580e9bdbb001fe69e9bcabecd1d40c4222b79e7"),
        (&[0; 60], "51118106e207d0513d1f2e2b6aff78e3cc55ded47d3840b014a3383dacfbd4c23df0472ff3a86ebdbb647b9c96893ed90569556c5f1c47cb8661278b7679265f"),
        (&[0; 61], "02ff1bb0f9139c48d78be75141b2075279a9b2981ef6ebbdd59a61562b1feb223b9ce1fdb46ccc5caccf96087f9e2c1b575cc1464dae216ca96033c1ed863951"),
        (&[0; 62], "cea7936ba49787b7f9c1f1885f974de885abbf280a523b23637da1ff41ffe34f2bf4a7374d110c707f7db97f7799df8240ecbb9bfd963b76715253985d040aaa"),
        (&[0; 63], "e602eb33a5053b8514e0c615167ec6d3999158f32b6424e6e1a7feef524fdbd7f9aa36ca7415f7d21a250b2c69421fd8f9ea7b3d264af661ebd3d0b39d432ac9"),
        (&[0; 64], "243d92f5a1328a4cc9f4cb6da60ee6f7b362472f7ad4fc117e3646c85061574c12e110bdfcd98d90f0d19b6bff5b44a7c69da1975c3a8522095eb9217e553c28"),
        (&[0; 65], "8d45561a1e1b74796d748a346060b0edff3f34002a40702918de5cd4bcc4a20832b57c9aa2ff8e5803ac21cfbe59a873f7b1e83f4351801b2db6875fdf69f054"),
        (&[0; 66], "58a98995c10da3e14ac9d76db1907232c239c41ebd25c7b5c126a0a7bd4cdf14342d57132b591c7926939811f20a1f3fa7bcbd2fe84b3ba313f93da45939043b"),
        (&[0; 67], "24e01fbe0536eb995e411c2ec57edddc0e7aa6e4c283e1a173a870327aad054bc35681fa2d0e607a595ec702c9993ec3ac393cc56735da8b35be560c90f0fe57"),
        (&[0; 68], "1db93e38705633009643842f8a65a3cae361bf679ac456c06667ab5a626698a3c1283d9b405486515f81a6364c389cb4907a1530c756694f3a6805ad0609971f"),
        (&[0; 69], "4a3d943785675c43a6577d936184f8e160f0f82b344f952ca65ff969ec00664279d8ce22df3f4874cee0fa6471814cbfaf616fee9c782f7861291d34257412eb"),
        (&[0; 70], "ad3e8a11a82b0a8a537a6861545715908468ecc210d4bfb46c685b766599a4d323f288f919f13d44bd2674b8002292de9d08ada336f907d6cf9bf1c33e3204dc"),
        (&[0; 71], "cd87417194c917561a59c7f2eb4b95145971e32e8e4ef3b23b0f190bfd29e3692cc7975275750a27df95d5c6a99b7a341e1b8a38a750a51aca5b77bae41fbbfc"),
        (&[0; 72], "f8d76fdd8a082a67eaab47b5518ac486cb9a90dcb9f3c9efcfd86d5c8b3f1831601d3c8435f84b9e56da91283d5b98040e6e7b2c8dd9aa5bd4ebdf1823a7cf29"),
        (&[0; 73], "4ed8ba5741d94caef309c190bc13d18eb0f16942ebea76dcf0c6db1a35311fc04611313ea7d0ff2228a131cd68a84b3872c93d75700601107b6addeaffaa7a90"),
        (&[0; 74], "b87bce38a829d3a6091c356c8dd561db1e1ebec59f03f12d2ae07a7b5117c98f68c13f552669ab316dc8f91d8afaca06e6e43b6aecdff2f9e70669a5d5ef9f5c"),
        (&[0; 75], "cae4089af8fea408ff3277d83ea67290a83d7cd9eb1611776d13c4b48f50f261548c2f59f1bc6f8f3cb5c2685780bbb787e66239048a343e4f64c390bb0df3c3"),
        (&[0; 76], "695375b55f209030e7ac4af76d739cee48d2d099a5d985705331b28f99797eedc69bdcb86058be72cd9bcf31ccb160e22b96236d4eb69eefcaab1bec5cb1b31c"),
        (&[0; 77], "7218fa1ad53d4c0ff957a5b6f55bbceb712cff8bcab07a1950abcf5f355262f21e1f92ead56f203e6c9489da67977dd81b0cbb62f80cbb7d788d51e2c0bf9df3"),
        (&[0; 78], "6b8fd1deedff1b2e8af3a21f32a37fd9e9f5bb3fc946c868492c177370de6bd9a8e03dfb4591412767c5d34be32afc569c5c6c22f67e4d1e171e8a140f9bf8ef"),
        (&[0; 79], "0a12eb12370eb20c563ef4ebff7b03b6eaa1d378e2c657651453076f460fe972fc218216d2ad70800441e1161abca0c36b4b6d24e6b12b7ed1d65e5339e4e96f"),
        (&[0; 80], "c449874bf12798a85265e027fdae6d670e65a2e74cdd625718a00d52dae3813fa400f24a8bd9474f3b03d5e3baedb2de32c466e92a0630d70f486d77783c99c4"),
        (&[0; 81], "541bfa78e81724823e60c506569c9b86972ce5c5b30c5229caa06e88529e74ff3c9c2099a9dee6fd15a97512d04eec890207fc3709dba39264ae8ad13ef53402"),
        (&[0; 82], "0198ebd17dde325342a98f1d6b2f70d9173c52a5db97144c3fae9cc600108343479ff7e9a085f1aacb128d254ff2d94aaa3898140742aaf16b8aa8ab6d81b0a6"),
        (&[0; 83], "71eda9fa5976f50edf2438bc2f740fb299f43775a8c22e7ef77aabdf1a2a6c8c65242d9c4467939c5ed271fde8499b8a88449b0b1206ee9e2a251936e6b46743"),
        (&[0; 84], "5b22e5cc72f405b7b57f213d375a0a84753f1e1d0fbf10b35f7d57bc084a19099c4f86d2a8cd62b00bf7e856e6d6444ea1f4687a2c6870cb9c82e8864c2634db"),
        (&[0; 85], "dbf28ddd3882288410ce28be3bcafafcb134ce0f31d098b78a036d509072752705832b5dcb841de1e5ca6805164b18cba4f33b17d3b176d3d0e364310697b37a"),
        (&[0; 86], "c8360b8d4882f299f8db8abbf3ca2bebdfb1388db9041b02c1d361688369fd0fc2637dbcaf113a240fb42195c7736a29be8e91580588bc4ccfcda071d19c2007"),
        (&[0; 87], "0ac11fe014648130e0e0cdc4cccbb7b82a62c929553e7a20af08e032a31b5a56b7081fb42a59c32266bf10c2f9ebe7b8d8dd49a8b195e140c8831ae3ce32098a"),
        (&[0; 88], "5b8c63038d4c577d71fbedfff910f276b6547fbeecf3be23b4e0aa11bf3469b9037302aacacad62fc13df70adc32380b4de907095f2e2aa3fd34926580d0dea6"),
        (&[0; 89], "1547f221823e25cc7d395fc51a8961b5fd70d0c0ecb32867b5691a30ee91a69925fdebd554c2373d4fb008cc4788db008259b40a2c102ef246561feb799d0d83"),
        (&[0; 90], "ef18bc1f1a49aa77a7db75304192b62a4104ce87232f835271d8eb049d406cd6f812fa44cc9ee20b45676827708d37c501da663d409e0fca25ca022a9daa8ef7"),
        (&[0; 91], "091341fa887f50b1cb93d573efd33441de81d1c0c0d7d19b49d254f6369a7685d3ef414d798f3d2dcefceb3aeabad8a75ac57a15b3697769797a1c479d9b248a"),
        (&[0; 92], "049646dd0c774ffb8bfc9acdae6d6ada393f5348e3807242be4d313c251bae37441cb1999335c44c87d3c3e15d42dc122143708b903618e1a565facea955874d"),
        (&[0; 93], "486992dfecc5d1dde6ea430a01688680013f24324658ada65522501192b29a4ea6a23a78427f08127d9c5fcb96f078cad328e89c7e940bfe70a90d4912ce6a7e"),
        (&[0; 94], "ea6b6defcd630860500152e812dff21ec1137734a77dfb9d1826dc87bbdf930a3bf1eab923d2ec605c00b9b14a1eda8204efd8a9067499f07882b8874041f381"),
        (&[0; 95], "0b095d1f69e23477fea2e1041803c1498deb43ad3bc1101ddeb791474bf4f1da5cdd6e8ddc18829b8182956b7ad5da2be0c60819c8e8889aa060fba18e17601f"),
        (&[0; 96], "7e7c8e8bac0b959204ec45602c92692933c359cfc309a840d206f6c04f9ef6f1ef5aa74b44138ecebc318e4f7a6351ccfb04ea9f6bdb20a18126a03dc6a6dd47"),
        (&[0; 97], "e5effd34575cee64a550a2bc764b6fd2e1a9930960e7ab1786977069b7b82dc985332e8769ba263ea77b1440b5ec495c1ad78deb34b8b096dc2d3bb644b3d102"),
        (&[0; 98], "38dd3ac8292fb84113b3fec177b6c1ae291765d5e24d7e54827079c0f79520204543898403e0c4c298e4970ab564d3925d20942dc78284197052b6cbd6e8b151"),
        (&[0; 99], "053d518adaaed7249fdef06f5c70c838673c0bfa764751dc9756952e46293c30f8c0810808209e7cd604df5d33a990a0084a15830913cca3299e4802dbbbe55a"),
        (&[0; 100], "4c6fa0ffb3e69a54ad16e0efd3d2f40991a38bcc13ade00ca0de3e3055baaf6efa47cb1735476db83d180cf145e097b6dcf68dcdd131a9aa94b2a3b876921e69"),
        (&[0; 101], "c5218757695f72f94b521fd89b92b8a2dbc8e98c62ceb757d16da18c47807cfad688305f12a7aa342035dee8a833d6d7588617e3ea8f3db5bd03f5e3861f20e5"),
        (&[0; 102], "c980f07f75265a6434c5907e7c3ca68db2b4bd92cc6eff0263ff0eba71f6ae1a3e2779d114b84169b99ef3bb80f09b7968946da470d27229d87a3c71bca10501"),
        (&[0; 103], "5efb6f0afc9e07c528a00547004d3e221e1c773b781b909aa0a20ef7f4a3503e69f78f1d9b5ab98eeb36fee7d91d2cb3e682bed2791df7d643480022da382144"),
        (&[0; 104], "c8d3b2c413a510f7d1dc414b5aa9612cc4243ed4e4b9ed2cb0fa8ef354e6dbe883dfaa8354be0ccf5982c0ac41f3f0c7f2bfe7c6e8a5086f43d7537764caf4ca"),
        (&[0; 105], "0f1646911b661c5eef5cf60da3c4dfba9971a07d933f8a719424b5c39d9ef9b552ee1a1daa057b590f8b435960bb32f7dc13db130194826937ae14043fae4674"),
        (&[0; 106], "a791ff88381567cf0d6ddda336cb01295d41c68aae8c2ed9931d90abc4b551bf58f89afea05e32fe42717b0a31127897641196371403570666d9fca646804b8e"),
        (&[0; 107], "7a148db32a30b5b866b2df9ee0da425f71e68bdf29b73fae5e9a8961014a08a55280049175938b5ae06ca8d4f4fc180f58e2c26203b4b53ab0a8d5394771dae6"),
        (&[0; 108], "f04d806fec20972b37e0a110c526d3ca9722a124b86ec00934173246581a6675a05107f1e734916e61dffea7ace647d2173055a53db073177b1841fca2285b32"),
        (&[0; 109], "b99abceb32f33dfa9e9760526aa3064aa161a4cbae20742343c467df65ace84dbb99ec1c825191d87c72d3829a62783f9c0184e283cb12959ba89da690e1944e"),
        (&[0; 110], "a5c6f64766d32cf1bcc0df102a5cce3a747b9c604cc58d5b140ed64c384bbdbfc8304c7c2c04d4e0f85f8e9923a500b94a348f1f49cd915a7f96b7cc3f0f87d9"),
        (&[0; 111], "c677adbab492fd76bff50e41bddae49b9c8fe0b47801a73a47632d8e895ccdc631e7f00f7f87fa5baec2ab86e47ea07072c829bdfe36f251e57d7f5507ff9d06"),
        (&[0; 112], "af8bd43e6f05532448f6509151a871db4ddd867f386aadb2b553a75e30f81bd3c2c79eec5cde15b0ef9be399ab166f4e1f2620934e584223d9f9504641a10f24"),
        (&[0; 113], "d501c1503b8ef0846ef4fef2a3383a98957296879a6047f3c9adea670666bdf8ba1c46283d99433bafab4df59f16da32fd66f1a43f7f4664b696635c92333e2c"),
        (&[0; 114], "dc3c64765ec7e137fd77c48d5ac9df2338da8b22762f7854e9d3a489b7921ea532f33913a03b62283206eb353fd1ffbb28b00081d2e60fec2805c111b30abe7f"),
        (&[0; 115], "c9456afc653423560f7970f3024750fe9d4efc7ee9dd90d85e0735daa0f01af8045403d3c0b0ac2bcc410d24bf3415a9aef5e39dd2bc0f2991af1ef1cb167c31"),
        (&[0; 116], "205a0cf0a783325d7606231caf692d9e1083a9e2345fd7d4d5d2fcf6278cf1ae0d31a2b3c16d8075e31a07cd4b20660b4d0b2ce480711d6ae82ed60636917461"),
        (&[0; 117], "cd57045c898e1557c77fe9f3ddde05b1c8737ad8be72c896c1cdb8f6159ac519663150241b4c440ac4c29039a0ccb14055e8d7bc67845c88b3533166d16bcf6a"),
        (&[0; 118], "b825de8b7983795cbce121a620938d7ed5eb1e737e2bb985582b033fd7d47314d793304156a0b9a3d4769b77ca7b82e6ab5ec44b18775e2d34242d28a32cf5ab"),
        (&[0; 119], "a99e77d5f4b404249a8fe522f1fe12ef8909e5bc4f2d554daa38d6a8869ae1170afb18bc08eae7d56b8b7c0948fc164f3c9ad7a40daa49070141754122847c9e"),
        (&[0; 120], "2b21d02277b4c98652553faacacb383b301f6ad5550c45ad6d110b07d7081419b06b552734e46655c46f3efef522ee8df585c3b25a51cc437b2eb2a46764b35c"),
        (&[0; 121], "399e73eef176cb7b9940577ee0a90587ef5d1d4438e512bc3a02ccb060715eb8c521b1a41b434f3ed816cb2578f3d273f27b14bd67d3d198f1e7d36a01f87e76"),
        (&[0; 122], "017d18ab7042eacc42bcf9f100a2ba45a14594434e76b3e2c4c59bb7710b13e99d6388d2542d7f0318bb8e0467fe46f8a1277c6d26db59f09f28e46fa8b60815"),
        (&[0; 123], "0f96571757c39f4fdbba7cbf79885e6b11bd8a96171a7d3fcfb9ba66588860d0ba5308a6dde7823501d8d0245f8c126fbd6600f38850ce548478567620ff58cf"),
        (&[0; 124], "99db9cb6f82725794b698603109a83de77721657535d4fee3da6566aa4faf9b6b6d14ee8a1e56c33187b062174fca85b7d99b2afe4db71f097c46dfbe9918cf6"),
        (&[0; 125], "d9d20bf97c580eec1360ebd2fa0e00738046860021ce7751aa66c374a09a943af7c126e556845e1dabf906d09f0c80fd29b492948717c70834960e959b3b6d11"),
        (&[0; 126], "7fe2393141aeca7da939892ce81f9614ac4c96f165994ea974b48e99ff40af526acbceb4661428680c1d6fc28fdef80bfe4e0f782ece7dbb7adf54e586461533"),
        (&[0; 127], "8b8956dd06ea4482b09478caa4077d15d75e81dfc17fe893cdb0729366091dc05dc3a95a530382f2e321e1b83a2d8ed97e85a7a4e4e50adee4538020a86fa06f"),
        (&[0; 128], "a16d68fbcbc9478268e6212438c63232c7f97bfa58e11e8427542b2b1e059bede9ad3a1fbcf91e20ae8d4b91c4e051a2eaba17622df73e4fa58489e432204363"),
        (&[0; 129], "d42e7e3e657337fede2434d280f1e7425145d217bcf70e48748b7128622d4d518bfeba00888edd5abf553e8a2cafb4bdc2642482f002a04228df07fae8b11d5a"),
        (&[0; 130], "c0952b2a0623b671079386d496084111c4e13fe2eca3b160e9f1a97988a82ae8add79424be397da2feac930360602e38a7ce75a309ef2a06a132d61b06c9a09d"),
        (&[0; 131], "3a329c2c1f31e7ce90421b9351fcab6bc6e523967efbdcbb961c89a2dc58d7b997daa72ec12c4c77694d54f6f96f67a34deb09b7cadd80cc4a0fd0a0ebadd52f"),
        (&[0; 132], "bcea48eb6c49bd0ec6e77347a372260c993ccf62a30f6310d82073bd3a4459ee9849539b7e141708162915295d3b4d6338e43361289b88c0d13123600afeb317"),
        (&[0; 133], "7dd85044f7219307015ebd1750eb05c298b28d56c935c1b7338cd233f7ecb2131828ffe0c4f33358f18dd50c156c6b8b5d1eb0f752e82671804766327ceb18db"),
        (&[0; 134], "f5c1ca35603c0cb02d59ffd8d21993a27f101d1791ba7aa4d2694389890f115fe6bc9828e3fb445f38b29cc02c0e76515214bebc16708660271306651b520033"),
        (&[0; 135], "fc88179420c89072adc2a2fb10d09e0752a76a27307851411fdc3688acb5aacdb866f2c0515766efc5002a7c51f03e3c3a88e38067b60ae1519b27b37f00ab16"),
        (&[0; 136], "1e9f80298bf229938bec8b39fa8b2ae4bfc18d04ce6f9ea9462aff3039720911252b5a85c853996bae9fbdf29080594517a0a3f4f5913cc405067b88e80ab16c"),
        (&[0; 137], "5c7f137f73aa2a8c6a42dfce04694188a6697559178ed368e7c8403bef9b0f7bda240aa8d02b18224936492e3b6c594d4c5ad749ee50f83916a963a3bf174a97"),
        (&[0; 138], "3a0e8dc040b28ec4f3efc3a8e5fafcfd1ca4456f79d8dd3af68a60119930756aa7f1c6d41bf9184b7bfcb69774868612dfc2b5e66bdd630e6b36399fa83ad2ab"),
        (&[0; 139], "ac1602e132631806fb1d2e81e4e3a2a9c34bdbadc877d0eb89e3f4faec0ea87a4bbc8937ff02a7b58c55706dd281283215d23a6659bc000086298e6d71966648"),
        (&[0; 140], "e4e49dd5ecb51949a8bfc17721e1f78267d3c9c7271900c35db6c09884a971b96c24f6f1805ffeef6400996a504a9b4c3d1aa308dae846a56815fcc0294a97c8"),
        (&[0; 141], "532f86776855d6c57be39497e2386b726ac29a454e4fdfbe53950bc0b30af651d83e6ac1f4b5e4e68b430d1b831035d9d412705fe4cefa0ebf441d14dd6507a9"),
        (&[0; 142], "3f3782702453ceec26061a713c930eddcf1de33fb0ecdb6dd43e160949b28f391121fc0f4b879b723751271bd388e076a425b5f31a1c6074dd80a055a01fd4ec"),
        (&[0; 143], "b64c8a8454d18fd30321e5188bbd880847491485129d99e75a253950266f5875bdda0491692b18098c6a1a03bc7affb7a2e56e4c25ac3de54ec9c8e25e537e3d"),
    ];
    impl crate::hash::Test for Sha3_512 {}
    impl_test!(Sha3_512, zero_fill, ZERO_FILL, Sha3_512::default());
}
