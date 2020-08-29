use super::{Blake, Hash};

#[rustfmt::skip]
const IV32: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];

pub struct Blake32(Blake<u32>);

impl Blake32 {
    pub fn new(message: &[u8]) -> Self {
        Self(Blake::<u32>::new(message, IV32))
    }
}

impl Hash for Blake32 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake32 = Self::new(message);
        blake32.0.padding(0x01);
        blake32.0.compress(10);
        blake32
            .0
            .h
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake32;
    use crate::hash::Test;
    impl Test for Blake32 {}
    #[rustfmt::skip]
    const TEST_CASES: [(&[u8], &str); 128] = [
        (&[0; 0], "73be7e1e0a7d0a2f0035edae62d4412ec43c0308145b5046849a53756bcda44b"),
        (&[0; 1], "d1e39b457d2250b4f5b152e74157fba4c1b423b87549106b07fd3a3e7f4aeb28"),
        (&[0; 2], "0800d05680abb4cfa6cd6b6381cf50ebaafb3178f5c3f11afefa215315658c0c"),
        (&[0; 3], "1e3d6d773a681ba30f3308d449c14d5f3284acd7637c841a7f06b0bb56aa11c7"),
        (&[0; 4], "1483f5f67efee888e3d6a5b805c6cf77266aff3275671a6f829b320b80e7f1c7"),
        (&[0; 5], "a35ebee194fbfbd42b8cf609633a928a674072097ebfe5cd11b5733ac1a4c15f"),
        (&[0; 6], "80f7f7df260f13a5bfdfd2e0d468d24968fa52101724c579b950ed5fc8d83e4a"),
        (&[0; 7], "d3c0918a40a2e69ad8d6c8535cca55ccdad019b42973738ea2b8acb49bc7c9eb"),
        (&[0; 8], "dde0c26ce4e9c6bec7eec013c18bd695c063a130dc3b466cd54376f229c97742"),
        (&[0; 9], "39c64eda32c9e2c7c3cf0ec3ac922d52fab22ff9322fc1a510da056db3185c5e"),
        (&[0; 10], "d587b96431cea9b76581e1097b05725cef44e238984e10f209f603111d0b4983"),
        (&[0; 11], "8b850713468d473d59a57985106c6ea2cbf895f8976015ac023ab06ff82fb57a"),
        (&[0; 12], "e7e09ded3a265ccf4563ad453b22ce3bda7305dc661a21360049f6d742c19f98"),
        (&[0; 13], "a5bb5f9545d6142afafb9f11a014b5299d5bbc4fa8bb683dd2276e10325c9dbd"),
        (&[0; 14], "36b49a3a9d900626ef763d493bd5de0719de24393ce3dca66c40050ecf079c1e"),
        (&[0; 15], "d7162f940ac82a65605c8c1a4600eadbb2117e62a3c7b3f6d004ed889ac581cb"),
        (&[0; 16], "36b09ff11f2641211f5e1dc10bff3b55cb9bb9d72b3c49d61937568c2ab40299"),
        (&[0; 17], "c2445b1b402e82e8e6d009d90cdbebd7304c9ffc7fee43d5b7bacdd2ff7c67cf"),
        (&[0; 18], "1332af1c099e1d39429991e2d70611d2d0ad67885e6dcb8bfffc6abb674f49ce"),
        (&[0; 19], "9fcb45f00139529d1d28d27dadb070ac5687d34cfb1070579e50567b62747279"),
        (&[0; 20], "d78d68cd43a886afbf4e5cfd5fa914b99157bc727482c68921e5ed389f0c0914"),
        (&[0; 21], "a7730f28c703bf9bd9d4ccf3fe415793a1e013b909a48d62d0b23fab1d7c4922"),
        (&[0; 22], "6969935724734de2431f25525cf8ed8068b6cda73a7cbb4c2d8a3e7d4af36cbe"),
        (&[0; 23], "6a1ddc945375cd1315ac6e48b217645ddffd919f244bbce20557583d3dcaa2db"),
        (&[0; 24], "a70eb1930790f83a3edd2eb8cf87aa35c7f349533d234432e932bdfc7f8519d1"),
        (&[0; 25], "62639a0be0226f4442e7d2356cb83f470df1641fcc1a7e6fba7725e8a146a65f"),
        (&[0; 26], "d520d615bca8f82b9850b989692da65e274773e17d42b1ba43fa4b34e16eaf5f"),
        (&[0; 27], "50195248a1d6c354d20dfe71e7132751a6c5b6e8525d0a7c8308beab84c23ac2"),
        (&[0; 28], "b90840f6ae9a2110b816f3852d2e6585c568444ca1e6fbae7ba7b185943fe200"),
        (&[0; 29], "4e1b50ecf8223bb42081de3cbdd89c4dab95c46582cfa687c64bb338f121c080"),
        (&[0; 30], "6e275244ee50f892e60dae4355c6f68e4c152563aecf06bce62cab9321913e98"),
        (&[0; 31], "bc031629fc881b8b70127754eefd6f972ec2696bbc7ee21397d1fd1477f0a443"),
        (&[0; 32], "23224cf0f2256afdfcb73858f67fd6976af5de57f3b65f4b9055e6603ce59a7a"),
        (&[0; 33], "c0a0c57fb8bb8859ff5e5d09093e2427640440d1e1d2e3ce3e3162821c90dd8b"),
        (&[0; 34], "05bd897d6269705e3a092fd12079d0d5e0b88c412cc68091394c894389e77917"),
        (&[0; 35], "a4676c3e679ba3464afc1e5b647b4a84e8b4958019a5eab4f22fb5f98932432b"),
        (&[0; 36], "c9f5f11e99f9f11b206f6bd167a97ac47883b82fd69dfd38517ffac018055db0"),
        (&[0; 37], "673f386babad922189459cf8070a0ec735ff075e016740eeaa195ca9f8b5f929"),
        (&[0; 38], "e1d5307bcec9737c2975a663049ab56c30bb10303a9a970846ed6b812056f6f3"),
        (&[0; 39], "f656c66b0a4dbabe9882fdeb457579b33cdcd173557c481de98f1afd4a70c110"),
        (&[0; 40], "33cbba74e022396a2b496b66ef5880929440685662df1407ac1b00caf86a2c62"),
        (&[0; 41], "e43654eb651cf184fa0a6d7c80df795b884f3145ee206a19daa7c4b59f47a6e7"),
        (&[0; 42], "e7719003117756867f610973b8b558ab5325d1d3840d675781702d8f4bd089ad"),
        (&[0; 43], "210614a844f822acbd80e848db6615fc19a45c37645d7c31994e97efb5c4c0cc"),
        (&[0; 44], "4d4b176126fe6c3a9304cd1f45e2ccfb087913dac4ddb9615d81d99fdff07568"),
        (&[0; 45], "2897e44f3ad94bd47929037c83bbf8404872ecd537cb8426faa7f0f328debdec"),
        (&[0; 46], "430d8d887489503330b0bc1887b88fd4c4bf635a9b089591a0e461bba415839d"),
        (&[0; 47], "06f124f23d5654b5b0b0e0fa294461571cf3826161601dc44810b4a5470fcad5"),
        (&[0; 48], "9f1f93449c9f962cf88ccb8761bc5d6d761203dd222013d9e29951f79faffb4f"),
        (&[0; 49], "ea1e7d6fc68f1b796f85ac6964c90907ad5ae102c371816152473a32e20e1dfe"),
        (&[0; 50], "3b3c6d35a9c9a9b106b61367a31de308ef1af10d225d2cf677aa199478400d1f"),
        (&[0; 51], "d96fac968192c85d7d710df747c585ef707ef5543db399c6353e7ba4f26aa44c"),
        (&[0; 52], "d2d6017cd74b6411dbc3319c2952e5d07567cc008099d799a48107891713dbee"),
        (&[0; 53], "5b354fbee6aa494e40516563a211e5fdda008982114828ae6b63c67ea7c938ac"),
        (&[0; 54], "e48be2d65ce7e11d46154b9559f819e41b4219b550e682d06fcffebfdf7c8859"),
        (&[0; 55], "a23e90be90c71273fb1ffb4b04eca3da0d78f63b6562c9b38e27230469e2eb2d"),
        (&[0; 56], "3afca2602886add57dd78991e2a86806b76627abb6c8c46cdbaeff937ae10adf"),
        (&[0; 57], "f852d27fd0f913f9fe7dfda97afbf3379eb96085d8c05ffeecb8e1da26627756"),
        (&[0; 58], "def47972cdecdfc49afe1a7f0c71684f8f0f0cc786ccfaa63f20404a2e779461"),
        (&[0; 59], "4f753973ca60262ca6008b85317c0aadd46598ac32c6af6f8e8f1522a6d504bc"),
        (&[0; 60], "79e996348b4125f90e0935fcb6a934e0e8d32cb87b61ce6164c374b748a2d503"),
        (&[0; 61], "db534b61faa6f1a55c46340fa49ae1040e455237b72ae9238d88f449d582437c"),
        (&[0; 62], "b85652540f0dd5e06287af50440d48eb99ae99305a9a5f094a3ba49fed2687fa"),
        (&[0; 63], "10e1b7676e35fe2072ef47fe4e81d3c217f5816b2b416bcef9626e09116e31e3"),
        (&[0; 64], "57b239285e0aada4d0787c417fe8d929f5e10d4202ffb2b90299a0eee186505f"),
        (&[0; 65], "5ce71b13365627b33e6c0cd23f69b1297d9e0b15b77396d7d6145be66cd1a0c4"),
        (&[0; 66], "ccace396a1b24cc2aa3d82cdf973fcce12341701a8093fad491f74302edae770"),
        (&[0; 67], "74a3656b642ea122b7243aa0ad0ee79bc730932de972259b3710428cbc545faa"),
        (&[0; 68], "09b5ec81b15bc686925b64eabe179929c61e03fb2dbc6ddd812673bd7dad72d5"),
        (&[0; 69], "aefed2de5684142bc3a2b12e6b4d938ff14651b8fa6a58249dd05e7a96eda56e"),
        (&[0; 70], "ef6a0396e26af452cd1614a8e35430a80df75a96c0bca618989d442122536147"),
        (&[0; 71], "e226fccf963d97366630c3416d5f06bb6c34d144a78cdb04420c0ea1e768998a"),
        (&[0; 72], "8a638488c318c5a8222a1813174c36b4bb66e45b09afddfd7f2b2fe3161b7a6d"),
        (&[0; 73], "072d3b57e008602ae69661dd5b894f9ff7218b33e69905013b7c9dd7f798b63e"),
        (&[0; 74], "043b614817720d133878bed8fb08d55a3ea98ba62f95d64a744b09af56b5b21c"),
        (&[0; 75], "eb3beea8936d7b31382bf3d1e735ba779f03397742dae0cedb687390e3b7c774"),
        (&[0; 76], "2e096b3778b18f9eea6cab6cccf4c4389ab2b1b69cf6821325f4b111899f680e"),
        (&[0; 77], "f4469ecf958433264ddacaa9c889f400c8d930ae7292d568f06a60a90c4772bb"),
        (&[0; 78], "ead387894ce42a3ad4ad5b1becaadb03bb1b163839814ba260bb9bc25e82c743"),
        (&[0; 79], "4443fcfd11ba3af4370b0c638d4ec34b1c71dca32e79d1a8dfb22dfa9acaca13"),
        (&[0; 80], "d63021501bae94dd57648719184fa357a1d363ec60a83643cb62ce606e34f8bb"),
        (&[0; 81], "62e10b05a7bf655ab93ca3393935cc2634aa833351bcce1328fbbd78228cba27"),
        (&[0; 82], "ec709b5ba592c3a80d13381d1a062d00ad7ec8849e62579dd2cfcc837867410f"),
        (&[0; 83], "4944c0b295fe94a7772659a6e418dcba526addc09d6b0faf9f5252d4bbc11b24"),
        (&[0; 84], "d97c27428d1b8ec74e00f5061e567a9570b39ebd1382bc5d9ccb6b2e1e8e6f3e"),
        (&[0; 85], "6977560ed17b9251ad163f52d0eba56bdc83f9e36cf26930d94e7bcd9afbd48e"),
        (&[0; 86], "00de1d72273706dfdf4d2a0e0e62d5dc64c19cd497b9cf20bdb4ec63b0121f4d"),
        (&[0; 87], "627449cc918d88374a9c1142e80f3fd3aa103310f636d53796238078b74ca387"),
        (&[0; 88], "3d13b8e0e78043c4f169f6258b8f83611735c4da6336dcc5735a2200d7c85e95"),
        (&[0; 89], "c26e756da1e61a1a0a55690d8b35963f339ba238d3df97040d7922011fbb543d"),
        (&[0; 90], "f6bc83c1bcaabe0465e70fac7c70c0fb02827eb6c84ffa67d15159ed1470213d"),
        (&[0; 91], "d443cbe726d1a19b8ae2ba0283a95a84ed679ae21b9c83b2cb49e3fa035176fd"),
        (&[0; 92], "2a18f5fc146f48e54124fc64a15e0a32b8b3bde1b8b2f8c25646803b9c433a95"),
        (&[0; 93], "a3ccb3402f7114333d5a5a37920b0b9b9a5853d7df47c599fcd6cbdc49372920"),
        (&[0; 94], "ec793a3001dd886e55928c8ed12a530a17ddbc11b7fdf5b08380d5a528efaf78"),
        (&[0; 95], "cdbf21e1464b990ded7c4e617f109a391a6b3805056f6ae1082c8b62ed684fc1"),
        (&[0; 96], "44fdb6ec31621ada94c48778d1db8c3d2434592f2a1262ea14f195e03a048a1c"),
        (&[0; 97], "eea747499dbc05c09db1078733bc22554f57f10cf6b22fd856f318a1496d5744"),
        (&[0; 98], "33a868502443af28e9bf89ab0f6c787745338034a77749624834ceb26dc365d7"),
        (&[0; 99], "052c795537611867da6bf38b279878bdbf93cbb8b620d963815c3f56f909ae8a"),
        (&[0; 100], "9b36c31aa9a17a90b5f7ddbfe7012ddaf5b65c4e60e55717a836e1ca9f685a96"),
        (&[0; 101], "4a4a103e8b2be5aee4f4d5d4e4b801581e09d732e9e2038fe4490378da58197d"),
        (&[0; 102], "6767e5e1830cd3e5be4ff1730e1efb20a7b0979796b1c4d02b498617383282ab"),
        (&[0; 103], "46aa26f9b1f47e296249cb7e429dfda4ca8b54479308caefff8e4f89f4e86ce0"),
        (&[0; 104], "86381d93dcef85763f29f90a54dd6946fe8c2d58ad48fe3cbe011f9951693758"),
        (&[0; 105], "a0efd1fb37b4485b81a2f4f6adc751e55493afcf7561e2293a9becd77815d567"),
        (&[0; 106], "71d6052c7d1fdec72bc8b1690bbd6ec1cedc3f2fe5901532c6c5412152d9cc7a"),
        (&[0; 107], "11fb04392cb5dd59c01188f26c2ebc0207748cd3f9a036b93b8d3d989c92cceb"),
        (&[0; 108], "65b1e0a1c65ca485e98cbcc4556e05b25387fa4cbaa0dd02db7260be839c3700"),
        (&[0; 109], "88ee1e10de8bc5b63b9a494bfa563f1b91a1183bdd48fba63462ef74928a8a27"),
        (&[0; 110], "fbcbe936d8fd8488fa1a577389db53ac112b036b85eaad4d5b12d05fc800fade"),
        (&[0; 111], "ecc01d34381b862fa0c652c84e017f16f65f4563a64c55fd9813c8555b5495ee"),
        (&[0; 112], "948d8174359bf9007a2d7c4bc07de933701d6b492e75777039f001bc44720a0c"),
        (&[0; 113], "86044a32ed845eddae9993c066d9bd154353788d62a0fcf5c009e65e3179d42b"),
        (&[0; 114], "2f98246d9c25f2e8f8f9abdf7e5299798b67c25f85e67cc112cf6907a9e1036b"),
        (&[0; 115], "d2029336bbc4d7d84bb2dbc73b6b7444be8044e52e1171d274dec323eb254506"),
        (&[0; 116], "4d6370f7f9fd50b664f3711d1508a30c7a03a2e45a361f88c0806b2b2e5778bc"),
        (&[0; 117], "f46509b03ea9b480d8e285163c9ddc92552f6a1876cd1a71c76054b80341b9e7"),
        (&[0; 118], "3fc8fae3acaec6cb799218134659a1b73b1b261fc0522759ca8e3bf1f9148b74"),
        (&[0; 119], "8272d63ec0906d7382ce2a85c73b45d2d554a9351b84c896f434104888635fa7"),
        (&[0; 120], "cfb3b73a39fcf60e5acc6a15da8258a7e41bbb09278bbc6057ec8e3194602b2c"),
        (&[0; 121], "ddf6e9cb9223603dbce545c8213d3b99f5f2ff4cb2e2e65c58849cac6539ff45"),
        (&[0; 122], "2a1aae4b8585b62516679c3d1037a60efc501c8b775ede372a9ea654e5c9fbf4"),
        (&[0; 123], "d15bf975b07a5afe8d66668f5a19c1d5d1ffaceba5f7e4235b7f8e9590a10367"),
        (&[0; 124], "8a054153f0ae61115097e6ffd45a21f50e13320586f593b7f1adae7c508d1b1e"),
        (&[0; 125], "51107bb77d7eeb3fb7ce23fa2ff1f1bc206f5fe5ba2b21f6ebd6fc4dabb4a82a"),
        (&[0; 126], "f04dcf5278e392ce55c8412733b91d5814580d45b93b672b6a345c8e1048f80b"),
        (&[0; 127], "ba2f02a8871392312d3962e18e5efdc88ff8d253c00e796efdbc58f520eb3607"),
    ];
    #[test]
    fn bytes() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_bytes(m, e);
        }
    }
    #[test]
    fn lower_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_lowerhex(m, e);
        }
    }
    #[test]
    fn upper_hex() {
        for (m, e) in TEST_CASES.iter() {
            Blake32::compare_upperhex(m, e);
        }
    }
}
