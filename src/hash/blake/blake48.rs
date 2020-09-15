use super::{Blake, Hash};

pub struct Blake48(Blake<u64>);

impl Blake48 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new([
            0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
            0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
        ], salt))
    }
}

impl Default for Blake48 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new([
            0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
            0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511, 0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4
        ], [0; 4]))
    }
}

impl Hash for Blake48 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake48 = Self::default();
        blake48.0.padding(message, 0x00);
        blake48.0.compress(14);
        blake48.0.h[0..6]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
#[rustfmt::skip]
const TEST_CASES: [(&[u8], &str); 256] = [
    (&[0; 0], "e0820c066f522138d5cb3a5773dea16db434afa95e1c48e060de466928bb7044391b3ee77e2bbff6c0cf1e07a8295100"),
    (&[0; 1], "f8a8d703fd654db9319ac478af593def821494cb23aeb57680a5ea1aea0a65cc7b72e69f6893efd23e5233511ea5d425"),
    (&[0; 2], "ecf864c04d2c5c6c86c58dedafed7db3b3c0b7366bd95e48993de5607290b8bb814e1e752100ec4134effec5df7f4b1c"),
    (&[0; 3], "4357d3d32479c285c3cc38ce1de9770c000113897a0fa9846cae9a3f936952ebc56516e1c7970aaccb6e5c374fc77681"),
    (&[0; 4], "fb02a0ea9164f9bc557ce040c48e6528515a56170fe5b26ef9e837db812c90fc0176ea995f6df53315314c47580f3256"),
    (&[0; 5], "3f60ec94144253f6dd10933aca9081ce5ea628a6d7c00883a7f5ac447ffa895a84aa9b0e0981eda539750d12b768708f"),
    (&[0; 6], "338639e75cf3a6b4dd8071c9e910f76c3b2b494c0f775e077752db689e15f89cba4487abe0ebd1ba07faab1ab1763c0d"),
    (&[0; 7], "258dcec3895fd24e4939b829434ef5b5611b5668c2ed0fd98ba354c55201ca6329aa279b8f145b4cc3f79983e11fad91"),
    (&[0; 8], "b301756d1c6e09542ed6105b539c62dc9c7927f6b08dc10c0ed25dee1154d645075e9895ae22abeda8f618cf31d27e61"),
    (&[0; 9], "091afef5ff5f9d8f01743c24eb40d35c15a0238cbdf84bcb8bb2e0026a9054f91bfff295120c374672b5784ef96667a7"),
    (&[0; 10], "56b60a7ae09d493c714626e3649bf90e1cbccd2f3c9d7cb1ec5c2d59bc233a5b1cc7bfa1a680fd93face65743b3cf3e8"),
    (&[0; 11], "96d54a3124fded243d551a0a586f9287c5d73a645aef9cc76ca2af1900d8d3abfcccab176b496484fe3ee64cdef1fc23"),
    (&[0; 12], "6306d91d52e3089ce3f41c4d261846a63481cefe0316691e95faa4cda167b29a8aa48dda79d189e4d3b6ef66ddfd565a"),
    (&[0; 13], "09ab3a0e2680ca53b1a4e3d47c2e6f227128101d00d481235120b6b509472a4c23ea2d3b34ce8451fbbbb29191ccb203"),
    (&[0; 14], "272f728f506c8d0fa2abf9d88bb9fbe96ba1d644274ba9d8d01caecde43d3d2bf2247aa554e2c40430508de41c16fa2c"),
    (&[0; 15], "a1ce0e1a4c572e8a462dfa9716d93f8fcbaff930005fe646a10be3eca38540dbc693cad2d7c56954c87e10b377050045"),
    (&[0; 16], "f2234f710aa062b04e1ddef773c593ebaeda5f10c87bdad2e5b22687bc24b22666947d4bd8e60ecf01c8359e91d1cfdb"),
    (&[0; 17], "56f702461d6fdd598b410ac66c7fefb7bdeee01b8a0b01ccd7c5c896fd571d0f7c2ea767a8c779d4973e88ce3ce80378"),
    (&[0; 18], "86c7cc0f9f99b48468067126b27e708ee985cce649ce75ee098e5d4fce74435c7505015478df51d6f11ae1804cab1fbc"),
    (&[0; 19], "e9046f7d16f6a400dd5b47fba56b89f42887b0c515623c24a609d99b30893cdd3f56629529e942e64afbd9beaab47f3e"),
    (&[0; 20], "cd77676e5104ea9fcdf4ff58b00e03efdf9f5cc946e6c33d327b1d4d593c5e81dd35c510cf44894226d8a2dcbd681f56"),
    (&[0; 21], "c85134b41098b2b6210ddbe686684259911b58efa4758663359a28d711727eeefb4c605833edbca8c0b311098729d164"),
    (&[0; 22], "468ec33c6526bf2b993ed1a1982783cf22226bae0c56f7ac6c58c19d02df69ff040e7f32ae23f4ee861895664b77e8d4"),
    (&[0; 23], "1d5372d5096852e11fbd62bf6a27aa33daac8dee3b951442a7799064ee76400233b615427d0d1578db4d4ab129156fd1"),
    (&[0; 24], "822796f8c46565878fc030d088ba1e64e20d2a73f9848927499f6d3a3c3cce4ce5caae6831bbd74b2ccf22a413094baf"),
    (&[0; 25], "9c93c46e7bbdd056a1a6b906049095611f23fff62d8ce99d218e10a1343575e9ea2b88a42f035761d1c188b3f14950cb"),
    (&[0; 26], "e8b780d5ae0b5a369f689d6c6505d04821c4579c5fde6193f5de69aa6589fbfc536df9ea2f3de359ac249baa2c0da55b"),
    (&[0; 27], "796eac25bf47dabc7f8ee46cd2b8ecd22ffa9f49dac220f5c9925e2894039cfb83a402de79f8fda117f449c09cfde020"),
    (&[0; 28], "813d7b11b4a73bdd74c60536d4d37fcf6f2bfe5c0e66cd7587634be5f3beb1d4a3d9538dd596a1c556f297193943f564"),
    (&[0; 29], "89eaaee611023bec5c18d3525d21f82afbe8b07778764771ca588111ed3dcdda48096bda81eb298d32cca614fef4b010"),
    (&[0; 30], "429855bc3fdf278e17ad756f1745e722b4b0ac1688a34abf17abc62915cc145dc1f21de8558a0ee162b822d9fa43a217"),
    (&[0; 31], "5c5f6fe661390d104329ed29674cf5318fbd32ea657d9bdd551cd59b788783ccf7bd81a44c689d0d78b90aaafcc70b5a"),
    (&[0; 32], "3259051d16070c7f1a2682a2b30022fae1bbc29bd56b3b3c43425a50c9a28ae9680ebf40d859cee0d3a8257806511fe2"),
    (&[0; 33], "c5c7020fa68649b04e1d4ea24ddeec2f9d2d5c070e22f3ba89b11c4de8122ee2c5db0577de2f5f8d27a027fb8e27bd27"),
    (&[0; 34], "665883e7ef21fba76b59a2d583c35234bf37104354aaf47512175bcc563c35fc603514f54169d7c99d21332246851738"),
    (&[0; 35], "7c18e5057ffe6d4174bdec45d4d0c12581d2c6fbf5593e1d2d736dd965f2a72bfb8ad781b6346b83d07298f02e67f6e5"),
    (&[0; 36], "05fa4315b4d361eeb7130835d073765353162aa2026a7b2ac0a11238829337da18945d3ed3d4844f5a63b88e98d276e9"),
    (&[0; 37], "de08eb92e172a5938f9881b630d745cfa98844c23323a33e66130f6278e6a686d8836849e14475ae18d08bca0f9fec47"),
    (&[0; 38], "82d0bb6c200b1f9e22568a60f5b861b4fd11d17fbc025f033184193cfc58ba885d4dc0455d8b2da99224895a25a63dbe"),
    (&[0; 39], "54373f20a6fce65aa071e44088b76a08f125a80c1601beef71370600a335b16ca739c1b125fd53c522a522de0f02b3e6"),
    (&[0; 40], "ff7ccd7e150ead7bd75b1b0cfaff6f3e4071b97ed6525f58e8d5c18f48088c1d90a720011202b1f8ae4d7f2937a104a1"),
    (&[0; 41], "8fbb0cfcc0c44f5be2bc034254043bbad5f0075f73f441671276a3b2911bad358a9f3ee219e2ba04b8340d278ddc7484"),
    (&[0; 42], "374ffd4dfdfa5dfa89bf9969c179d37eeb7773fd8701efe7e0ca8be7de362d1093076e78702742e01939694d84964fa8"),
    (&[0; 43], "f1b7260a13590921978ae026c8c2b3d2e66d8e54491da02aaf125c2552bc8f6ab5f9fda422be395181828df2cbd1b56c"),
    (&[0; 44], "9928aa7e7e0971d32af4451cfc1fb19732eeecc15d42becf63ba68ae5aa723600c9d98f4f61ff6523bbabb765fa5cfc8"),
    (&[0; 45], "1cc4fa07c8112e476a59f833167dbdb2a89841d42a6dd1145bf528a9bb71faa7467712c0c596f12644e60648adbdc633"),
    (&[0; 46], "469ce5914a5cb3337b2ba71e1a7ca9a042ebb526761106ec59424203e90ccc45995bea8f2489c2801ca0a3620dbcd9ff"),
    (&[0; 47], "9ce098e71063d64178c5d1435afca66f7e1f3750a6946e4f8ae05fb774cc772684719139c5e8a6c07a93e26981455386"),
    (&[0; 48], "66d52dfc77a783b8d48ba5a48fc69536d7ca492fccb2acbabdc2f05296ec4901065bf38299e2360bc2a91eeb2e4368b6"),
    (&[0; 49], "d7f4d9f02004b85c4e7edf67cda4cee4fe6806994947da65ae67709cd6c00a83ac631e50b5ee7ab94bc1d4edb3b3ca64"),
    (&[0; 50], "6ef22f1e0ef69423d6505ac1404da7e18c4f812a3bf8a128c13f9ebc0b8df367bed60b9fece6ad3e0d481ea94206eb90"),
    (&[0; 51], "ccfe149442564cce82f1171bbd079dc77147bdc3f14f6d6b7b130a9037c83a502610f2c2dfc5af86ff12a239e446b125"),
    (&[0; 52], "da8403324ebba6a6cc51859f2e8e8347f7a875c66b60b086600e2d095ade66e737a7a5940010d61d1772022b8c9dfb17"),
    (&[0; 53], "f6f1e62dfc82d7066ea2986657ba043f303dd25dbbdd1ec601bdaaa285b9441bc955a4a60c59909ccf007c2bbb6b440b"),
    (&[0; 54], "60bba8ec466360096d43e8dba9f0b5b2bdf9e28b21b3b399dfe9cb801b875729ed75b6a41bd5f3d78346bbfaa38f0447"),
    (&[0; 55], "7e96b994d72798552960d87f0f84b6cabe28589fe70b736fd7bd75418ae6521a6682884951d6e3713a5c2b51000e36b6"),
    (&[0; 56], "99c371c913b1a0fddbd4af9ca0264b692706436332a88e8cd07f4e77dbf8677c810488b098e8ae6855c658d33633bbee"),
    (&[0; 57], "ddccbcaafbe6440fdc54691f6bd96d0138a2f354dc8e4519e0aa50b34474b6e29b52a9e91ec408c8d7540cc9d85acae0"),
    (&[0; 58], "213669dd12e2cbfb0aef0517fdf211735dcbb5f6027d81fa51f4f1cf899eb96f3e208f8d9fade4a8685cc8abdfcf74d9"),
    (&[0; 59], "af926efea038f476ec1d44df729b5c623ea79b0a592ebd3f2bd3f99b55783268446f840a5a7b6154257354b733bf1433"),
    (&[0; 60], "f15639aa2ab37ac2564e6385ad4cc7bd5983aba686510ef6040ae94836f407b88645974cdf5eb3508aa3003f82ae2f83"),
    (&[0; 61], "dfc00fa8260b14e146470835d1cac5216640ec679334ae0492b4e5b4554843ec7f5abfdb1a4a31da92df47a07688b26c"),
    (&[0; 62], "f00b34c3918171590bb28b32c3f293b6b96a7da601203ef887028dc7e494e05ea9b32a896d4e1aece5b45fa3c1f507c9"),
    (&[0; 63], "0796337dd29f7667805710d04b8722c6edd87f419cace6e74a1493481fcd02fe20f4ab619511516d88255ba614b88cb0"),
    (&[0; 64], "f93aa833d48e6c95bbd3e8e4d001879ee1a804cb15a5b0a88b4b449f7b8ae0b759c55e1e7a262e2c8d0cdc19c00b670f"),
    (&[0; 65], "ce995f923bf2698032620b3db07cb96f936e5655ebde491d5d518cd79cab1b3ae5aede4f9e4cb3dbc13caf104c48cadc"),
    (&[0; 66], "985a92107caa5ca30f4088454f15c11b2acbee9ca33824739b3be53f6e42a39bcb074c3296ba3a7dad819c0e9b40e585"),
    (&[0; 67], "eec6f4d4ce4c84c4c7bc9cf37ebaa8668985a3aec8beb77064682ae29e2ba3caee6657aff0c7958b5a68b7398446307d"),
    (&[0; 68], "45b204dc1fe10681477826f4fbbad6a037c454198462a2de2eefce138e9ca95f23ecf2fe5e08a98d7e985a0d96c81cde"),
    (&[0; 69], "ce3456f700752dd408c4cc57ec98ff493f020813d61d81c4d26b79a023ce3fd3f2107ef67994adcc6debbef5ca75c809"),
    (&[0; 70], "33817255b5adafe1ec1ff8ad28c9db775fafdbd2047039208a72c151a26a907f53d98b8f88e5ad58cb0087bd26e1f565"),
    (&[0; 71], "662324cda47ff05afd1bea0c267e66732b137c3d500651804348c563a375d90c8d5ccb7630e8074096938406d7c9d911"),
    (&[0; 72], "00e42cbfea052e57e70a3fddce278a76bce937406cefeea6571982f5fabbe602e371570345ea15e4beeb1db28bfd6ad7"),
    (&[0; 73], "3d2298eeef4fdf36bf5d5aa2f474a67bd1ecd64e7ae14f9a84efba3ce62dba07d1ef4f11b893f04bb9dfb7fae9438f17"),
    (&[0; 74], "ce0c088df7484fa7ce16518692c021fb2c45588ea89f3ca52cf0ee3df0830850e87faeb3770ae004fbe137b35c576441"),
    (&[0; 75], "e1a7d947b0670794638da87684815b099f1f5ee88e459b6d90babb15b387e326c26f515e960b4cc7e01e63aefdcc35a6"),
    (&[0; 76], "27b6fb1dc395adb4cb2190bd3cc32e25421006cb1f8b66df1fc1a991fa7a1d1fce360ca9efa0357b6ef859c52f6d7ff6"),
    (&[0; 77], "1c34c368d2b686adb64c34dd7642779df47fe582c99fec2d8484a56de6001490ef5b31f8ba60714fe50661c115e289e3"),
    (&[0; 78], "c83ccb9cf53311d8cd711c848e4e6db9008501c0341bcc861316be342b0cb78cd933e1f5dce86bcb20b75881b9cd51f3"),
    (&[0; 79], "7c01ffb174453e1245c20031d6aee3171f439b10a208eac028956a89dfc478a32a8eacf883fa234fe4f6d078d7fedac5"),
    (&[0; 80], "891c58b5c41e2c46ce3294491b5f0f7dd0518ae419d58f8ebe1928d125bb7c842eb5fb51876f9aed6103e5890ef48f9c"),
    (&[0; 81], "31656c736d2d466eef84babaa65da32f7a96feb1a21bb25cdc542c9ac62e9286fbb1abfd65779c8b8034ec21adad4105"),
    (&[0; 82], "0f1cc58c9c7fc1d8866e2391c7732170b9889fe6dceb1b047f286a59ae01805436d016ebb8333ebe35b0b259e57dd85c"),
    (&[0; 83], "4e644a9d60a90fc748a3a221e301b61ea9c57c44570ace86ffc8a367e664331bcde019c0aaeb12c22bed49ad7a57089f"),
    (&[0; 84], "34b4835a05ea9baf7a77bd68e95850715a8b38b8d901b6116d95caf9e462694be45709a29a3ca1dd38d5a2d5fa747562"),
    (&[0; 85], "f1a6d38a49f030995bd3796c1aa15cda0ba8f82cf127fe77383547a7cd3029bdcccf39558cf000a5d0a58fa82c59ba3f"),
    (&[0; 86], "f6efdb97750c13f1f0cd32a9d64a8393260d04e7fd7a0cfda9593d4edfcd0b9d21d0aa09a256c5533860b076d7695261"),
    (&[0; 87], "8e2752ba6549030243c65b793d458a1f4c3ea325072744a1f5a022c468b5a53191c88208bef13816845d840f1e3c39f2"),
    (&[0; 88], "13074fcde3d2a31848952879a9f8eaeac0ab5b9c782ac5ccde445e92b425fa1f4f2d678fb84503b57566ced602a0092a"),
    (&[0; 89], "521d1724e01776b60ab80b3345fbe4857e65f0a288606b15efc10e789b2baedf1d10e485946a8ba06eceab4c33244911"),
    (&[0; 90], "83f2d4c39b493f77f8fa4356dbf150fe907db4555ed59bdd91c929c8191e33e1c8ffad7aa4de88548406e08998fc7ad3"),
    (&[0; 91], "723bb4e2c7dc050854741088a496f3851565725d91665e6ee60a0d133a81e502fa4be39352613df2a287f98ee62613c1"),
    (&[0; 92], "92dc57cc05b4d6a374a8ed3b0a4984b1b13d6e61374f1c6ff93db83d291a644c1fac0612fd008e4c2c826cc761d75a8f"),
    (&[0; 93], "9b3c512694b53b73b2fd4d076a28d08fd816ffbed21ef2dfa4edc004297086f52cd0d18c27e27df1bc7a2ead50d9868d"),
    (&[0; 94], "2f595d6dabea870646cdd4d75acca59d7bf14469429c7f1a4a63115cb968a06376d41451b769f5b3501ccfc3a2877ecd"),
    (&[0; 95], "e4177e1c1168720665259cf0831ed2fbf8697c27997965b0f12b4b9fc65832b3ab0c80fa5a98d9a79f8998d2d238e4e6"),
    (&[0; 96], "01fe8940052761a7fa123e17ed6576d1c7b2bb0b21e4544dc1bb55f17f5ebd04b37688cf5bfd73e789fd57b7d8b59bd0"),
    (&[0; 97], "2261c79b359852154687e98d1a9daea3385d385d544d7134f2e51e71ea3129330b07054360138610dce7bf8bb5f58a32"),
    (&[0; 98], "98f36b459379c507b5a3df0585b22a6c03640dda846881710edc9f978d84a98d477ccd474f527e7f185d47635c8d7de2"),
    (&[0; 99], "574ed559f3bb66187f89e8ca8d0b41577607c2d27577b653cfb4c5a92156c4b569b33c62700632b667d92a2d0d6268aa"),
    (&[0; 100], "cf478c645b30f3ab5630b66e7632966ce8c80c5bfe936cfb3def50c9bfad67611634758017f0bd0507d0533b1a3bc9ab"),
    (&[0; 101], "43b410597bc4d962e57631709272768b17b772f6edde8c800609a493fb053620c2ecf9205552f9d79884ce24575bb091"),
    (&[0; 102], "640067a24b969ff212c3d0fab7addd6cda65f429a98d5d5a2516f9af7008e39b14de784cdab79e1b34604e7729820f43"),
    (&[0; 103], "c6d9801625f5b6e2f0203292e1afc6a77a79f837eb7faba842352dcab34a448558d2469c5086375b1ab4996d7ef2688f"),
    (&[0; 104], "3148496963c33e83fd0f64a9310395bf9fa1f3eb3bbe16cd19306926b61411c6e585a2b8b8e354a014346bcd7ad52768"),
    (&[0; 105], "0dac3dedd93b0aefe35de8987b78c64f1966a27ada8337b795d4745f55bec5f843c63717c225548207fab2cfe991eec4"),
    (&[0; 106], "ca0480871bb3e618b43f1200ec746c140b8504543fe577e19f011bec57ff66670744dd56aaf2fc2df3764b87f2f54c26"),
    (&[0; 107], "b3facf0551409d3f405ed813e398bd01def2715ab2ee81a6a356234fdf7f02c3c148c5e37569562313a8b57054787594"),
    (&[0; 108], "7bf894ca625d709b6a891efbc23b71bf44265a44b80aea6c4d90e1772055efeb23652df164aed1bed5cd78ec3e1c4433"),
    (&[0; 109], "6506024f550aaeb392f57464371244951ee2a86c11284d803d2de054bff749a5ad97a7cb6b00351b431a68315c736b58"),
    (&[0; 110], "1ece502429727f2ed7273424758780b6c35dd3e1dddaf323b2f0dd6dee7dcc9987f01e395fc9acad106a733ad184ad05"),
    (&[0; 111], "907c456c825f92fbaef23d35fe8a80b3310853883668f156c82d82dd927933bd32d491b0997f14a5c8af16e75e834348"),
    (&[0; 112], "d6bc9263e772eac1fd84f65c9fb2dc73fec337c2f1b65753d020ae5f468c68e2535a72dda7c865b54f012e4440e2e341"),
    (&[0; 113], "db0b5ead9a54c7155335518c6890f366e5acd68943d86481f1b0deac721fc35dba586610ce3f91b06473458c03db0d62"),
    (&[0; 114], "f16c0db2dd2d0b178a41ce0e877d1aa93520f52128fca410c812cd9ae0a9dcd76671c706dda8c570a2265644682bd87e"),
    (&[0; 115], "5cf6e2c682e830cdf2307f35d730b52cc0f79a634c650da224e43b0dc2b900ac584b0adfb09c6c0d45d90642967df87d"),
    (&[0; 116], "14581b825c577e31a6c5663d9924fad2225e896e1fc4f767b876458c64c9bded67ccec069dfa8293bd07145c5b1f2980"),
    (&[0; 117], "48458a37197e98960fd8f565fd26104b9cd20e97f289e0d4874f0f227d55cf2e774e5699a7cbb3a8b834668873eb40f8"),
    (&[0; 118], "82691978bf68baeea0426a3776aa7784e74d2ba1855f3a20b74af5c5608204ca5561b05457f7766cd50ce62aba589567"),
    (&[0; 119], "5c4140231ee7f9fcfc58996638ea8f6995eb6a78aa9167fe847d34a91550944ecc0a226be2656e1959593820ef95f830"),
    (&[0; 120], "e74195f7ad114513145d639d0da55aa1bd16c73f9e29f42c88e8cc6d035781be10505da35be2c9ae6e64334ccb2be8ff"),
    (&[0; 121], "8d379633032439e0830b407b2af4365138822905fcab04ea1409cee309ea9cc2b4c68f0ec328bee3ad2c5af9c33c96b7"),
    (&[0; 122], "171123ad3240f088e8791f372d3e22ce5a3e80abafccb35a520d5f3cbaab9fc5594213457f472b18b49e579c7d1c7584"),
    (&[0; 123], "3057b40ba3d04bd9a5068155aee42cc77187863aa9d1aec63e5a991831d7bcd06b13b662b9620e731fcfe738888b999c"),
    (&[0; 124], "6e1a7e773e4183c458c3438f2baa28536a19f115379061be922e2ce51b74abeb1f4fab835e615a02c081a7cb7e4e41b5"),
    (&[0; 125], "a0655c6f7a7816b5898744346678a5a447436cd6c903ffd2345d8eda1c4a48dd63ddd6a73fb51ed556d5c6d79582b68a"),
    (&[0; 126], "7813973de7d68a16d25e8c3c779ea8b1e8986eaaf266b15ebf08b78f40c37daab0793f20602596cbb6be3039a6e5b25f"),
    (&[0; 127], "2792a15e2b846a63eca445442b39d0bfeabd9c3457e1838398fb071d3e86252559670fc9066c03e0515157084e0cf74c"),
    (&[0; 128], "61f0a74c041e731245b03664b021ce566e60f0f05289e62407b4032859a255479e0eb9b53416fe7e03107b6eff2fcd72"),
    (&[0; 129], "ada5bfa92935d227beab2749fbbfe9705acf5c7e48252eab6eeda3af13e71b607bed50da0aeddba36d88c52bfdf33c10"),
    (&[0; 130], "06b75b25c1fe1df668761bdb1108f64c3dc913b8973fbef05f6fd7b312920d3a1029e63526d86ff01c69b955a06d4294"),
    (&[0; 131], "1e6764b3f1a39b805bdc01c7ea5ce0dd1aa4f351f2d707c689ff6de5938a422d05dd0b1dd727c110c68bfa2a94c3294a"),
    (&[0; 132], "4efc98f8099a07c5be5da79790d7acf5489a4e14c77bcb1da8a6b7c700ec213302dc46043b54972a83cd199bcca00767"),
    (&[0; 133], "b07b0ea8af2d263d13c1e1b150b6154451664c324b6962fb3bc0f8999a9b323047ac9fbf84815be4a63c5c677edffd39"),
    (&[0; 134], "b728f45145720413886eb637d139341c30bb24823c8b506e0ebf7b96416cb9040a5e5f8f2ed2ec5bcbc2544899ae4e79"),
    (&[0; 135], "5cb0431549242f2da7fb8498cdae021bdb04bac560584fefab3dcc81580e9c92f0d71949810f445b56f05be26b6a9942"),
    (&[0; 136], "2c1e13c6b7925ea979afbc5e089891005fa9639ba2fd6867adf0b086f3df4c1d1b900e35e1b0d400e35c2f38efa1459e"),
    (&[0; 137], "d65fbe5e8ce591140760e2344e761d21c44855b7c132fc4de88df97a7b105a5576967fd4f465001915de38b18c4d9a04"),
    (&[0; 138], "e4328f652f84da4694d925ae91216d137e3d1e0dcee3ba98377d987a153b443a0be07564b5fb872746c4d745694e59c7"),
    (&[0; 139], "ba753842f409e88ed381766e82b2d549c54c337cc066453d8234cb05bd8744de2ac3cb9bc9024f360e4cf67fea9280bf"),
    (&[0; 140], "858e4b990b8f7dd9aed4a1c69e0203ab6e014cba3921d0c5328b1638586fb988801b3743ad6d0841f0c155f419b31b60"),
    (&[0; 141], "172aada8f2762c385fb87626cbbe6d47c2a8876c424c5cbaedd0b0ec255884dca1fdf59ce12a9326dc365124074395f5"),
    (&[0; 142], "a219fd15f9db97762712b0f43fb896fb982f714acb9688d14c332d5adc04941c5154461b53b817b0c487bcd52521c59f"),
    (&[0; 143], "44160b9a3024fe96746629a9ec6f195b1cfff3962330149fb2fdb35f9e5244ff6266648d213971f70c6cc4e3396096ec"),
    (&[0; 144], "c802316791fd7c1395d568c94cc9351e27fba17b5c990c9aa920bf9bd1611921e283a7e600f7b8949cfa4deb2f8a667f"),
    (&[0; 145], "e0287f8cbc3bfe5e054d59bba126d038a71ffeb6913d6ffedcddaf75f99818d4a1169857ca2b50a9b526a0bc1796fd93"),
    (&[0; 146], "3de82fbdeee118c93fcdd017dced4a18da318921ec91e33657ad5776c58bb382f4f0bfb9875aea8cde6cd8ad616b4ef4"),
    (&[0; 147], "63874b243177aef9041b5932f0f920f60aaef0f5cff3603fe6059eff99b3c4f5b01bc67bdc73e7c399cb54fbd5bc1803"),
    (&[0; 148], "b4771a86fe735d171d5b3f9e46372b1c174b34812e3a113a3ccf98d3f95f67f9d6c7f490479f71d4d851fa0d6604bf61"),
    (&[0; 149], "1140f119e120d124775f52949162235bfcb21cce0eac3becaec519800d6073ae91780caa54c9d02ed429b07345529e2c"),
    (&[0; 150], "1a70b4a98ed0f79efeed0ed024ee44d04e22faea1d0f238f0545005e5972519e430e633e03d5cd9e77ef6427090184f3"),
    (&[0; 151], "239683e77411752d97ef04b741e19b368e7412e800d603a2c61c87f70874f19d1ecc0706b012bade59197040b70f344b"),
    (&[0; 152], "434ddd8cf3bb7a803ca46842d8f0c9cbf4d7207d27591813044462088a26cd7cb4154a5ae9b0a9ec67b598325cf95947"),
    (&[0; 153], "94cf2b815afd9524b7056cd2d760c31ae827cd7fecd945269fe3e9661220fcc4eaf0d4dcc6650d0a8dde0f993a2729dc"),
    (&[0; 154], "406447d582e20a9a8ec6b8c57e83499b01d5869e6b4b61d773f76a16f3a94bf4fa478cad2065704015c995c5f0b8437b"),
    (&[0; 155], "4ae295863f7d13d6b328fa1be32419889756f85fb7881c277d22842b943570d41ea0212334262932215b13bd031f7095"),
    (&[0; 156], "fcf84a9d2250ceb6685f68fe561610515f679174cce6d238fe7d679d3d58a2faa472f04f62ad011ee9df3e5e25815e72"),
    (&[0; 157], "a608bb331c6ad815fa1c82b9c822fd7482fe36a5ee5ac5d65d6d2aa138982f2aef1459cd9f32ea1c0f98af0cec0b892b"),
    (&[0; 158], "a9688879f70c44a698ce2789a6a790b1736accbf24222bc1f91422c3b4f7deb0855f01bb59b7d56167035eb693e6eaaa"),
    (&[0; 159], "df0cc997afcdb9e4babd2c8661797d024e2dce947733f0b56de1d6f2ab85ccf44f8004a3a25d54be2787d040c0f85934"),
    (&[0; 160], "7baf9a7a54f64331b4538bb8fbe54860a3757700a34a0eeddee8dae0c96337a0bde74f8c00625e765626aed2d753e76e"),
    (&[0; 161], "b87f6c324bc067c1216a2f511c20bb3e3d681c5b146b873061bc9d66e41d7f3b3530a3ab78c43658eb09a9afe36458db"),
    (&[0; 162], "3a756a932305ce31448bef682e1fc961196b7d840e48ee1ea4d9c3fe9545c1246901333574ddcca6aee02d754648b422"),
    (&[0; 163], "31b2d3db1be8a39fe918083b54c703c3ea7e461ef3ac4b5cdb203182ebf2d65de9126ca11c04398af6df56ac21186342"),
    (&[0; 164], "d2498eb79656cce31e42a92c719fb8d25eb54f919a0075eb21194a463ff070fe8c6b000a97dd380e0d45a31020814f61"),
    (&[0; 165], "434dbe1cb0827eb68d5bca0d13159de2ba5c0b592ef7d5747d444a668df629ff5a5fc9373a14e35dc709e447f79086ce"),
    (&[0; 166], "35227267c98a6a2455b5b71c58b07d6b368a15bd9a33f9080f4b8947aadbd623cf7e72ea342b6c2bf3a723e24d88990b"),
    (&[0; 167], "18eba4e00ed37167adeb16da794e3a9f3aef1dabadf08e0805f6b86b9147cf6a302229b33e3a7c923527d04ee2193694"),
    (&[0; 168], "85e31e36dd51d2ecd97328fabb0acf8fc6b442419ebbc7564bdd7b93f5749dd359bd4641dfa4850b343d1dd277a77c01"),
    (&[0; 169], "6c83e453f56840eaba7cfb0588f16b95556cfb09ef660d3dd3d080ddb0d2e72847e75021c14e605dc77dec3ca7c8926e"),
    (&[0; 170], "948ad1797dd56181fb36cd024473aba0574e85a394d2077f400c7e795967d87ef98c7d42dcddb4c12da94f2b071561ba"),
    (&[0; 171], "df1db3f175752284e3625dad48238d8e51027cc3596c7636051e8f837c8ef1f4661aa05f84e2d47cdfddcd9ea5a4286a"),
    (&[0; 172], "bfd3d1c51b204d3b2f38c203a0181fbdbd106fbb3ccf891b47cc43937dd22103febe35087dcfeadb7e45f5e83a5bcb1b"),
    (&[0; 173], "b909428588ec3d1b7474c3bc3513e74cbb5ed84b13dc8168cc5a75ccb87b6110d8c6c5db8b5bdb0a8ffbc1bb22d1652a"),
    (&[0; 174], "3629df61f5125da96f200399e0f5757e6d8dabf9443b86c3194696f081cefcead941bed3b5fcd91988f7df82f8adb920"),
    (&[0; 175], "73b008e658877ea830b9767ad028951d199a7e1cf14f3eac3d967c745b954a4b8b2b8fb1c1fc6cb0fcb5218bae4a8140"),
    (&[0; 176], "cb7bf70aa06004dbc6985bd3cbdde27b93b5c5b1ec46e946e8777fabfb7c5650125a382bbd57229d9834cfaccc4adc5f"),
    (&[0; 177], "78ddbe8ddaa2a579766f4045d9215574f9f8a925ee1f07c75f0e917a58334f1148b26a2d5b00c51feda0d91c21a7db84"),
    (&[0; 178], "ab37dd1a460203681ca14cf1add44d1bd6c0fa5cfbfca0ddeddecd706ad1aadbc6e570a77de183d66c5694b03b779798"),
    (&[0; 179], "a73e1a6f8ac31561c9c198f7ca39558a86adeaf3ad74c0bc3b1cfa3da4b49b5c0025a62c4573aab7e3a8750903fa80a7"),
    (&[0; 180], "950a08975d2ad1b3e5aa06141f99786b8eccde0bf200bb7b4c1c8915893195391f8deb16f2721e50b5999a0c8ae4be6a"),
    (&[0; 181], "db83b8d22657dd0567f48d7fd4464fc428501abe700e999beb08aaf59d2041eca9dc7cfef18d7152f97031e2d0aaefb3"),
    (&[0; 182], "840dcc92e6801832747071694e7024eaee101ec0db4307f01a1b218c7c9c1ecff6a9cf3a2bb48fb0fff2c4041f3d42a1"),
    (&[0; 183], "b42ddcf723ed2cdac0fadb615cdf0e5ccae9017d672ac1373a9b9b0e74aa40c191f25875990ed2c5b41f9051744ec3a9"),
    (&[0; 184], "7c714598610c3a17b6432ca4667d4778c94ae84283b8d0824a6c46a87c548c59eefbcd44186b6747cbf8ec6d9882bf53"),
    (&[0; 185], "fff296ff2bb7242e62c9dcb2ed08aa0800370fc2778001ae98541f8faecf4e65439ddad5836f956e3ca74d4f291dbc94"),
    (&[0; 186], "41bea621095ac90e929741638a28483fc489a2954e3577ae13619422e0dde7c7873226cd3501db9f437a03c3f269d58a"),
    (&[0; 187], "05f25fddc099f319060d2c6523d726d8720b437bf0032e667d934bd20cf0bc4c29a0c6a7bc84d0bf28b285a3b1bef499"),
    (&[0; 188], "6d96a55ddeb07a2ae8510b3c952666feacdfb82118a1ba8c0874663715b13f05a7f3bdf682316a29ea3993e11f8d9ef5"),
    (&[0; 189], "d1cdbad08bbdd9c49666537fe61eaca56218f7fe1ab7d9f5bf136210a8416d33d451190c1d28d645408eb942ae2b67d4"),
    (&[0; 190], "9e82130fe6da18ca2cbe2b6d07a87b81bac291a30642e50196853e3f33a567b32e420b80c7de82f94c0ae03ad76bc270"),
    (&[0; 191], "5d3be4aa7e56dcf0793cdcfe91e9fee8f82b6ddc3f76d590f9133ff80cc50ce1e5e935ec1ee879450f919008ed5eb794"),
    (&[0; 192], "d56b633838a5ada8c4383be9e6e3479dafad1c1e24a30253e6e0d2637d3aebc8b6ef76df946e7b05383321ec67157d2c"),
    (&[0; 193], "5e43170ac3724d7e2ab5891a72ce405cedf09ee339af1b3f44a2c8637cbbf41b1ac555c5d0f6c3c3d1121be8db89bfb8"),
    (&[0; 194], "3df2b79668e5a34d882f529616a585ee8d4f63c4236d228ddc16181e771aba69d15c9669180c97ffce50ffe9a6acc102"),
    (&[0; 195], "45a6dd8ca358120050cecac43bc2fb7f306cb9c40beaaeb43452863557009f5ca87c1c92deef9fc2a17313cdf3bebddd"),
    (&[0; 196], "833d1f8dead84db99ac068880e0a9653de0de77c3a7cc86d46312834d6597f12e06ea68a931a9f3192552071e537333b"),
    (&[0; 197], "95a3483d32486fb816dfe2d2f1eb2f782e641361093f0e299c51a3eebf5316ef63d77f868a57cf0a34c697ed11967017"),
    (&[0; 198], "7d0094c65c2552f6f847ffad89e700124bc622fe85c6033ca7f23c6925620cc1e7e4ec203f944f5ae6694107a019ca77"),
    (&[0; 199], "e7dfcaf37b5733692f6d3e5780af6d92009748b6e3d2249933fc6b4dbf1981fa7014036be2432962ef7b7569ef12e3aa"),
    (&[0; 200], "a5569752fef46fa602f1f12bb87fdfeb03b6c4d29548c522c9dcc4f91912af19abe0b27982dfa3578fa53e178bc6ee8f"),
    (&[0; 201], "d84a15c5b7226124db114b0db2c41b0ccd7baaeab8e6467471433209733379e62dd9cfb6dc959cb4c711f47f6f7d9e6d"),
    (&[0; 202], "6cbf285f90ec6c7d5a302251f43fe1b111af9cd46b425e38eebd48881ddee9b2040874dc5d0f2cca93f88ea44ad81ff4"),
    (&[0; 203], "f0daab3d9ecf549daf49ab4d51ee4a36bb568abc2504bdd46184583782762d24d5872b00461fd0ad81553b337afedf37"),
    (&[0; 204], "2d6b195c156cac69924448a9c7ee202697a2b9194736218219b3d492935fe14b4a8b049bab61b8eeab20ab1b844b00d8"),
    (&[0; 205], "d635c3b3df787f3933fd2524b44fe92b5004f3c17bdb4c4bc839818ed4eb9ac483b6204393ecfd0f7620a5fd7cf2d7c4"),
    (&[0; 206], "5ec3e6b898bc7d23e6bef529e4fcbdbbc43ca342ce3599d55561c7ea93ce4be3ed59d723f89a38aa83ec0fc5cd355e57"),
    (&[0; 207], "140400f0243a0f5a402612a0e5a3d27cf1a175c64165aa52d45ceae96efee61694e7740079a918886359302f748c1f46"),
    (&[0; 208], "98de9e6dd878b81942c676e237781da9810d356aee2b54dd27e345e23368b8492d63ec2114be6af00beb640e1d6ba61c"),
    (&[0; 209], "23f7270a020cabf751f93958d8508e10851f833f60e8fd90abecd24955492fc98d9102f468211b2d35a376c0b88986ff"),
    (&[0; 210], "c4f3cf6a611be918fd7f6bbede8d7f3c673981b794cf3912e56f09628db23972cbae3a5a56fa5d6ee6a4c274b76f5e9b"),
    (&[0; 211], "2c743cd549a6b31077938ada9cfb5f5234188ae37cdb7d89299558a9c9f7a923582bea7da5e1874f0b6db7375a761692"),
    (&[0; 212], "6218abe161808e88e403eca5ea87d8c73a417d360974bbcf7039003a4a1a5950e6d17d082cdc025e0d216655271f185d"),
    (&[0; 213], "a12d0050fd21b9bd0d4b3e82a18ec0cd21415aad84af90ab35cb785bb855342036a89e3ee249acf505473ae87d91b42a"),
    (&[0; 214], "c6a060bc3b18edce11b1f2e87bf98a98f7d5551b2e3053a10d34cbacc03b653f808b336dfe64e3213ce5ea32d4ca4ba3"),
    (&[0; 215], "5eba8d1475fe139f1596072f71c67c47e372071379f3b0b5a8540ba72b79d19ca2c230afd4e4fb807ff3b5108bcf1651"),
    (&[0; 216], "b0f52bc3bfb9bcb4c7d89e883d3418013e76c5ee4ddeb2e6c6bc5f03bba9c14ffee7991cd5a3d4567f34588d2c95e6e5"),
    (&[0; 217], "bbdde23d6773c0c02128edcefc482bf8f5a150348870b3e10be9fd153736dca450e25dff08abf7bfc088e5ddd5016eb1"),
    (&[0; 218], "3fd1f09bd3dd635087f29d702823ca595a607e31ef8d25f26d9b9d38681b50616a5d3a386e2aee7b3d0790e88dc87e15"),
    (&[0; 219], "2b910f3bd8804173d60afab2c9e5df7422fbcf0151b4303314d85950289a44f2ab7a25c2ce3ef2ae24269c249c1b96c9"),
    (&[0; 220], "c92f41e55681598616289532bfb80612723b376b1b9e5f5b16ffac338121847007032039393d14b74f08433bfa29665d"),
    (&[0; 221], "648f987fb9ed093617984453e7f508f50a67a4118e0f99ceaa03459ab41b1ae06b93b06b06417f8c7bb3863027827638"),
    (&[0; 222], "581476c01e6e5c05a9a2ded74077d9870067fa60ad68060704e5b2e233d4e11201d5b046eef2435d583f1150ecae2d70"),
    (&[0; 223], "974ced08fd86749e665db4219ae152c069de96bf123ebe6219f8dc3e64968389f70f263607a2cb8a38bdcf7fcd765b81"),
    (&[0; 224], "cba30e5e4cf1f639d284aff96ee85f11472c22beed513b4e1cb855f6b92cf8f240b842cc4039fad138947e1d867ef620"),
    (&[0; 225], "d61d377752a70d861385f002438d2416e6749e955b22cbe30786609b9dac3d6afde561b3f7b4f9df42181daecee9733d"),
    (&[0; 226], "bdaf986f4bbd98d4663bafc9ced2b3ddeba935af97f974fe67afcdee2ae3000e26cceab9e4d872dd3a28953072923185"),
    (&[0; 227], "d7a0d0badd6af6bb5d42d8f84033e7b15b22585fe0a81c031c6ac6e39dbdb1ea0e4fc8fd7e56e013bf7d225b8553428e"),
    (&[0; 228], "60f63b0fc129b8792aa708a3ae5e805912bc85e8ac88add69a05ce56b5fb6c959b247e4722d284860420bdeb12f9a645"),
    (&[0; 229], "74f2785262ea6b8ebddd669cecb129ac1ccd6d49ed2eb9ff38258a7447c508d955313c15945f17ca4337cead5399d483"),
    (&[0; 230], "29adc4d06b4fa7b059a8ffcfa0ed9d1baba528864ccf14a6a2abe58480a233cd1b6ab684f0d4f7e910abad2cefb02c79"),
    (&[0; 231], "fbe1c0c05355c81662ba266e5784c20f7f4bcea7e8c8fdd271a63784b70a0360c710aa17d3676f7d16085318e839c558"),
    (&[0; 232], "77a664ae3a43c23243f75d027619f67185e11a7fd830aba8c320332c541282b326bd9c802485d12c8a4f2d852dfd8160"),
    (&[0; 233], "844b7246ea5c39a9084136ddf1efd09fc98a28599c42f4c8f4f7ac41833d23746ed4fb76c9cfb069f39488c99a7eaa52"),
    (&[0; 234], "54dfe8adecd60d9a0e9f654b803563e5646588d70f9d1f258ae3cd9018a9476537f40333ddd49a22b92813eb3b454642"),
    (&[0; 235], "02118ea9da8b2db81e33004095d0cedc974f586692b13b10745ed1e4959565ad0567cc7aab9b3bd30653d4547e12eb8f"),
    (&[0; 236], "1b16b3422d863786c23864d93336648378d42697be589e57e8ab50375119d55f7d71c60d631147adc6413ad01f960e8d"),
    (&[0; 237], "a52c6aaacef4109c3df45ab8cdf85d8ff454962aca971193c81fbfee9f509d6b8cf087f931a53641ccdf88ea4d4d126b"),
    (&[0; 238], "5fb9ddbc2662045befb08ba7ab536df6ff861b1df0ffcbbfc5a3f9c621b92101211a0232658920548bfe061ee857228f"),
    (&[0; 239], "b6fae011eaf9d29cea09c78e61118a2b99d589881947365a2297875f663128ee29b72e45e8dfb9a0bc60d1c0b9a67964"),
    (&[0; 240], "9ba8c04cbbb15fefa69977929ec427406f9cfa3e53a7dfb10b594c2347167cc0da1858a5cb7dc8c1e72d1712e0fe205c"),
    (&[0; 241], "86844a322a3ad01458fd4d033e8c95305964e3af873778ba5ba7e500942f26b9aeb8f1e16aa4a88c2423cb2d8ede7adc"),
    (&[0; 242], "c83aded20f361daba1d32470b3b0956187a5528314613a4d16afd3366b80931d7d60d8fb414ffc0e5fcbe1b8b3adbdde"),
    (&[0; 243], "1339b6e91184b7e802f8c63ece7e6e0c5a42f8b4a45fb8f27fb4e46a08601c944e8f070ca1faa99f5ed55a1401e5d61a"),
    (&[0; 244], "5797732169772a9f0ce87ed934d13d275ae41305080ad289661df2ca905f496e441c8f17b0586c13cbecdb699faf1c87"),
    (&[0; 245], "5ab0aef8efd2998ffc5d87bcb7ec8ecea3b311d665c5b61b46b9eddfc6dd3cdc285763abc4ea1938442eee7491b315ec"),
    (&[0; 246], "01d0dc086e32ced0298152f98b8b5a621e42dc3ee4d86194151747d1307ab5412023b14deb00208de2e9ea3dccec8b40"),
    (&[0; 247], "6562854bbabfbf203307bcbac359cbfd784003801bba693dc2e2171c0cabcd9e0147fba36d0dbf9ba1359b09ae6e4a2c"),
    (&[0; 248], "e16180a18435f6da2776fbc53750c24bf358abcb239f94569ead52faddf37a7a0c575005ea5c2c9e76f310d85b5b09b4"),
    (&[0; 249], "6cd6e4c36f3b6f587d399f56364e0f683b31dfa890c110767cabec13343e655990f5116fd1a1f9ce8096197819d076e2"),
    (&[0; 250], "aaf57703b565ab5c042c1a15ddf5b2ae11b136fa1a1b47ff9c6ad9516a2e8274d1dcd7f35de2d4dcbf5ff69789b09706"),
    (&[0; 251], "077100cf7e84470e15ff84bb4da8bc698bc2f27d09aa97170ed61d8b59678d92b04c7ad8bf556573d7499c3e6f1fc771"),
    (&[0; 252], "1b554465e74bf4bfe70930182864a70075ccba116ae727021d3fe7abdc6633811fe24a3afd2aed1b4908da54a337ec97"),
    (&[0; 253], "70e6f095ac2adc604bef6f70720e275c2561ccc786c80522dc074e018eadb8c34bc1dc033cba538a276f73894a320502"),
    (&[0; 254], "3285ad9a96abffdcd298ddb85698ddb79e6e2c6652c9cedd436d8c908fcf70e2837953a7ce10eec5a066ce7bc0255aa9"),
    (&[0; 255], "011e73991d8e66edca37c9014a2e23c07ec1fb1c947888adc214ff35f39ec8e8b1e3ed8967dd2aa81a5912269debc1dd"),
];

#[cfg(test)]
impl_test!(Blake48);
