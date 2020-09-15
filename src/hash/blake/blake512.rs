use super::{Blake, Hash};

pub struct Blake512(Blake<u64>);

impl Blake512 {
    #[rustfmt::skip]
    pub fn new(salt: [u64; 4]) -> Self {
        Self(Blake::<u64>::new([
            0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
        ], salt))
    }
}

impl Default for Blake512 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake::<u64>::new([
            0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
        ], [0; 4]))
    }
}

impl Hash for Blake512 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut blake512 = Self::default();
        blake512.0.padding(message, 0x01);
        blake512.0.compress(16);
        blake512
            .0
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
const TEST_CASES: [(&[u8], &str); 256] = [
    (&[0; 0], "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8"),
    (&[0; 1], "97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3"),
    (&[0; 2], "0cd686174dc1451dcf2e54bcd55b868bf84f54e4f6454afd599abd0f3361fb85f09dda2c7c6cb9a97fa6dca2ed8068c8e8a69b66c4f8bd819cbfd5a0bd9d8e7c"),
    (&[0; 3], "9991bf7da00140dd4e193e370984b125f1efda4585e08ee08aa318057b3ad6145a763bc07851c15340f31b326a79ba3f840e63ffa0bfbc78cf68635f8d317113"),
    (&[0; 4], "0d5aed7c12fc24127245e83c09e6c25f5b882d490f0d7e22e096af5044f7dc04bb174b3e37fea303e7c359fbfd05eb0e78c7c2d6131e15920d23546954820230"),
    (&[0; 5], "e577a5f0d264b7304f91907fcd6f415d33a95540ab5aedbb31bd97e776e12c845d57e818551e40d0324d310d14f9ad0c2136df3dd40d282c20029089820f69c5"),
    (&[0; 6], "2ffeb9a090e1f48fd8c71e7f650238441ccdae1c7539d52f23f563fb4b430294a8bdbd454336c72a960c16319c748faa71d1ec5d850277d368f9b0c64f299653"),
    (&[0; 7], "5a0418839b047eb2ea3c0700b5c5c7d4e4c780e1088f58ae629225444d500df34b2467f89346d8a508f925299f1babf60c085a36fcb271255bbfab996131e17c"),
    (&[0; 8], "386928c3f6420b61f533f74cb48c6e5e9c3494a8e4cf3764fae960c37c076afe01b81b12ba7fcf19d7077877b1f015ce3fd6bf0a8ddabdc38fbd8d5eb76d8ea3"),
    (&[0; 9], "b2ccf7e87adadade35549f506441416c997e4828c60408eb9485e3dfa75fa9f52aca779d8b2f08bd5c19e6cd81344f315bcec311a4526f7530f7f045246d3c0a"),
    (&[0; 10], "e6a5d4d02dd56cabbfc59b163f932cd5fee410bcb8e8bf74679f10ab54c06c627d6c74c62cb4c6feb1be6d47ae5940161981b233a459d8ccb5d48b4a33e6b436"),
    (&[0; 11], "998cd4308b49759d78ea31c4ca37483e14b4bf8b58e9bc3fde98a9b99fec3531e141ad29278963f949b07285c474de8721e3a9db7e9b10fe05f497029e7ccdea"),
    (&[0; 12], "33c2166811ad4ff66339e924b91b72ff9c0bb610ed6d11136b90c960a1abbb5292e799bfd9c92763ed83cc497653ed02479006c2448d1545a427e9b2de2dee22"),
    (&[0; 13], "dcfb9ef4f14a779e07c7ff16287e0054bf30763a1720ba5bd36dd0692e5dec0a4155a007aa041a543fc4cf7c0c5f7ef8b2f71ac0ae24cc52ad41ca25ec37bfb4"),
    (&[0; 14], "5836e2094890e80d37b45bdb7c172f32eba070881caf5e230e5e6fd19af597e3baca1546f195f224e680600b56a54cf8ef5606e56ab2e2c8276ca1fe46885bc2"),
    (&[0; 15], "47673364de23657be821f68fab5858419e11d553bc011b749a31b2cb8f3f686b1647d6a49c53d9408452a8c6e0b29e7149939343309578652ae838a7bd27e196"),
    (&[0; 16], "f07ffb3e7191bf9aafb8bd1e6d0e0fa73f199507176d1e392c8de3f956cb2325043cf6d5200c5427223b9f1675e309776fba981877d00a12a8f9ad133d4d92c3"),
    (&[0; 17], "e9c407190817ee9a931fb9d9e9a1639224fb97088f4ed7410c770b2a6258cdb3c638ce1c3f374c20f7d58b2092d67fc06e92fc12258efc5bea074fb9ea60281b"),
    (&[0; 18], "f86583f34cceb2bf480fd21a5d2049e767832a89435410f98281f319e61ea34d8ba1b31bf05c1307e110a2e7cd0fae573556e33454e4d587ead96f2048eadee8"),
    (&[0; 19], "2be1b5946ab645a8959ba3abf2c546f20895ea20f287f779a11acf640e9b4e4c903760de32a6db4f75338deaffacffc957bdeee1c028a900a5b308e33c895ce5"),
    (&[0; 20], "94a2b3e4f62f92ed4d92809d36e91fe32681d3815d3b349ecfe8776e9d2b6c65427f339ef0ca0bc5c1810d2439881afc95d7977106a6791e666deb04db4614ae"),
    (&[0; 21], "b72c829a70f0c2797c5bc31a79c5c6e320ef14c9c0761631497c874803b7ef3cfbf885b1d28084226cecfe364d04e6aab537676e4122bdd797d46bd3ebb70de7"),
    (&[0; 22], "7d457bd3d494135a6fdca4441d45bcd32e42e868274c78bb259ac18aab98e52b895a7e995339a97dac81038a1693b528ff989c2a2f1e8abff486238ff4e82825"),
    (&[0; 23], "b30b338dc8974e74153a4fb84d0ae39f8b0cef421648681452231f916667a052777ea6896774b78070532d062498528ecd8970cdc60179f579d0814ffe585875"),
    (&[0; 24], "7206414a844afacfe2130832ec241963ebbaa736453c80d8cfeaf247065317575a63d5979df026a70e30b419c63dd17349ac3f591e1b5e759f9bce0ad50b9011"),
    (&[0; 25], "ff2589434d3336ae8c86927911043a97926c75d510cb67b50299564a5f3268e22af819ee3c63295bba1c0ffface424bcdb2df127ce7ad5bf2deb10d7657a275d"),
    (&[0; 26], "d06885b7259a854e079b71f7f4ff7d35c8b2e9cac58e304e56e71f598c1f0c43d644b26c5916662116b902a02d630d931559bc3e966bc301344930be70598294"),
    (&[0; 27], "8a8d36438f2e6674dcda674bda87ac88f8dfdb0766d6bddc086d7201cbbbed15d7e888c9c77dc4277a1e83facb1edfae65c67eff308f65b256668ba849e48581"),
    (&[0; 28], "2758e9f0c44eec24c1fc98fa3ff5e0056b548a0f4141bc711aa1bad60d7ba0eeb1697d0f24a2322047b6a37b014ffcbfdb5712fea199a19b4fc3d9b3f41637bd"),
    (&[0; 29], "72eb4c7d9406bf3341f62eda9ef34a47af740ffdf67374358952b683a200ac5399f857178d83f130436c382adaae761f4966b0dc874f3e3e0d4de031323a4e3d"),
    (&[0; 30], "2d51567a2075e2d2d5dfee8c2c966b6b435a09fa026e9ec5cee07857d26a3d207c20b615dc4d6ce94219bf0607b64ed92e20433989d84a04807658a58d1ef10d"),
    (&[0; 31], "2f8dd67740d0900b649d090e71feae3243c7239352f2e2f943685e7be95d200ccccc5862c628dab158777ef65594dc967eeb2e50199f0ff68f6c12853cb805d6"),
    (&[0; 32], "6fe2a4b96f71518b7603e5c63702588ba816885aa1ce5908de31335e1147346070f06fd35cacac1c0afe82d247bcc317d28704f28e8deab0fd17403f8de241b8"),
    (&[0; 33], "7fe8235e8c39e5ec13ec7505bbd7beabb5d463f15de5d4f17dc228e828938db2f8c3065225ceb54daa359b2272839b9c97d322872d7492b24158b2d24e8fa584"),
    (&[0; 34], "f65751381afbee3281539be27995e8e5a546040bbf7046b8e96ee78c2ed3cea18e869329633a5e6db860c2029dcda14afff773d282379efd27c96479fff289bc"),
    (&[0; 35], "88c1d9b7bcf839522f77804a002c027f7a5ceda8fef3da8c40a1bdd8dab73aaf684e493ff8ea2d4c059fbde4c7885b8aa44505ebd83231a170d5d5bfad11de6f"),
    (&[0; 36], "e0089f83add434243053cc56faaed3fd8fd347c29b47354d421bf3cc4ccfd726a0d57e80ca38dd23a914209f0a199c6028ab223b9c683bb000cabb2fe38a68b7"),
    (&[0; 37], "275844ac4ab78384364784e3dfff914ecb3be4df2e1ecdbc120125a1493860492c27e7e2f500b67db7d1f540dee1bb11bbf12f602047d4d447557c9f466acd63"),
    (&[0; 38], "afa79a60f588395f2b951323b1de4a63ae84f2098aec2d766b8766de952c087f5dc00751932d2ff4f4c6b6b2c89724378ec328805973ddea44840122def4d891"),
    (&[0; 39], "81b74ac4d2425fed9c9499ae31cbc0c01abc7c44f96e40ea010e1599fb926544b02729d54c0cc72211cc4e75213816762186cfc7209c1c27ab229f79680be8fc"),
    (&[0; 40], "9051d35c11c95e4c69ee98bd9486b43b73c1e0a8afea59487f9ac628b26428f10186753fa326a90538500488e18e2eb2423c0d29b3636f84c8c3896bf00848cc"),
    (&[0; 41], "79f7e8e69cd459a9bf76cebe697a7b1b5d67e797e8f0adf6432e3f6437e42ee0d4391edcc2156d056e6a336e9aa85c7c0acedfc76ee49e9d3c1bc2abd59f549d"),
    (&[0; 42], "2cf3b0416d827a0084483f232af3a807593073b1281664678228243e2cd0cd36c9996aa58a9393b72537e5ebf04f464e9f34acddb257769dc4837f064c206d88"),
    (&[0; 43], "679bbbffcbde6ebcc7fdf78d8985a8c58402a4f972bc5843e3e8bd2f7b0992e976c0cd3837edcb68dca379f96c492c0b44349a9d96b4748f0c1ca157b78de50f"),
    (&[0; 44], "977c5e34e818531b5843d0d6c8720e341e13aa465de1526a40ecdb5048b1cc0eca5df0b3a6cba920a827d686b9703431c05a8f8ca67b1f3c199f40a4d45db6a7"),
    (&[0; 45], "a70403cd12b8e0e45ac3e8538a358ee7dff274149f96d467c89beb3d85829a4421d200b5d3b05b17476f34243b653e02f8275e1dac0e4fb3354f3e6c37d93e7d"),
    (&[0; 46], "9da9511693d515f8f067c2d40b6cc99e18de1a99f643c382739ccc746b9568ba68b37ca6e08ecfd27df21bf034bb9b907471e710edad07b450e47cbe0627be53"),
    (&[0; 47], "6dac4e3c431dbd2fa1f458c4ce8bdf55e2679982def5ffab77727d67d7b9b91547227a0537df167d40502b22e7daf5175a274e253c42362866656cf675949b65"),
    (&[0; 48], "6d294fcf5e266dc7878f24670425b0d169e295bf51ab3fd249a7cf0d5e4de9f5233e88519c5f8fce1aca8c70f8eb080914f3cf970faf9e91c2edadeb5e96081f"),
    (&[0; 49], "c23a7e2d2a83ba970b1cca470d284df66a6288d01047765057c71f1345cdf1a8652439b8fa389cc3bd7dc4e23e5f8d27c1f8b5819c3749c8144a78d92182431d"),
    (&[0; 50], "c2c6c12c5aadd20da03bac87e36f4ceef3b9e4ed968656cd5732d8e616ba5d2e73ed6ba1860de71300fbaaacae5cdfda95a077b1a11885e249350a5c4aa9216f"),
    (&[0; 51], "80c3cfca3c4ee8ac17c7107e90356d1f7c931b58ec86c445a18bc26d5fea5ab350db4e8de5b5b2f7c0746896e2527e12b2c919588770e07ed95046102809a56f"),
    (&[0; 52], "55ca629beb1b59fda6f92fb1876adde528765825af0d8a75f3d38cc19dd9af16820b85bca29162d42be0a23861766eb87824f0a1b4bb4abf744f178be4e4b10b"),
    (&[0; 53], "145b0d072cadb5af7b594b130c4ad0eb8ffb863f455f1fc956048cffac8a93d4f476fd4c309acef3adca12edfae514239d59e9df5c09c725167b0d54a1e58a94"),
    (&[0; 54], "d7163034268cc35270c0e6416fa606e356ea309e9cca504d6903ee5013810639ceccae8d4713bc8c1ff56d485a084ca78b5301eff8d1bd1c46793d9cdd6763ef"),
    (&[0; 55], "add529ded06f5bc824344d9b770ec6379b183122eb5f4b829c3f94882006db1af3da51ce2287936d5f4879127bc98edce7016eb740165b47b7829f4d370b9229"),
    (&[0; 56], "c0ce3390f7243b7957cbad3d59f27107924c93b4befd58660c646228331dd6675c59c5b6c7f7abd125d401fdf7550bccb248877cba71e4a5b918452844d77c25"),
    (&[0; 57], "78df77dcc711148408b147450a793b4668d4410601ebb246ca19ad7a69d91d8627c9b996e57437c297b3b298e5ad39ac8d0f464dd6951a3f0f971638fc86d5b4"),
    (&[0; 58], "f6ecdc084f75e490848cfd626413692410bc11fc44d1e26c9e24557e9de6d46909607c397a8627bd840b61ca8ffea2ffbd5f63f95df2c5573f3ec2c3ab15b127"),
    (&[0; 59], "9340f0da11c40ec3a9eef3eae237748dad943df2bc595a6099df256fbf90108117cde48c83ccf5948d18d2131db5807cf0835cd609d80375918d2a28c680a846"),
    (&[0; 60], "4917fb906e025f4d08adea21b149a51f1ad53673f029371cf985c2bd7525d3ef06b6527dea2f98c237c74043b050ee8c22c480cd789f447cd1241d9b52f8ce60"),
    (&[0; 61], "7a36b92c7c4c9a54158630702034998dd7b6b1da4558612a27ee2e6202dc3d893880eb5646384034be0ee67f96509769378b26bcf9a8c9846a5d550e07523ef7"),
    (&[0; 62], "05b733fa6e6d8210a22047bd101ff34e573fe0ef780e3b8a3702353a817a1bea0c0f6027a3b87a2a3429f9579004a314efbbc839bc3a76cd13f8f140d5f14884"),
    (&[0; 63], "13896d6f3e092a84f47e430e6ab81a047c27236eddc89a70c715a6a3e36eba8a4c27972f93c867366a0527a2fe2d59215fdc3a76aaffefc15040ac39f84d39f7"),
    (&[0; 64], "2d5368f488178be0b4bcb37501916049381cfcf82615de91f121d4a04e572423dbcac515472da296160947a132cd16685e2363b9ec7a63892e2bc3eb3daa16f5"),
    (&[0; 65], "d93aa7872b7799053c650552f9851de5d9b8b23df5355737b064a008d9b4706e36fbe8cf3df4f17669c72fd6eac5664f95a74d9a484e139327b04cccc0501ca1"),
    (&[0; 66], "c9c37ad257e73c33e44423f8a0a0fc66080553533b365675a138c480647befed1ae2ff99152e53f61b39861fdc58f1106522baae5f2aeb2a8b7a39cf2196099c"),
    (&[0; 67], "4327b29dd8a797ba5c439c85a2b9ac8517ed93e4709ef96064ad7aec7adcce9f4ee637d30d76ce9c59b7e1eef5b885c0d60e44fa625a5370714650e3203390eb"),
    (&[0; 68], "f163fc626e81fbf9c8f1de41bea2f4eda389f9e04f97d4d2c9da986e9e75699b0fd2eb2007ab583522f75ec9bcddcf1d79966d828093ab423db218f80876bc3a"),
    (&[0; 69], "5e61ba8c3b3d59a822e09645af451bd5b9c54d4d025f6b5aa1e4d95534584e3d5666354413fa8366b0d8a7f92f4d1dc0a34bca8314cebb63017a0be40a4dcde3"),
    (&[0; 70], "3bc1a2c69b48e25ac85fa83e1eb6cb8ed8f87dd50ef572a504b497787ab2f864cbd7e0ce1333bf31e5167174d6ba2d1021ca14328bb4bd4c2c8a835772b07e63"),
    (&[0; 71], "40bf401312ddaba3ef560246c33491846f693aeccc798a14c64bf0573aa26088e49019cf449b0159b02843b4cbdc297c4171407ad18548d16b84f94d506530d4"),
    (&[0; 72], "2f31e729e269c7f22cac8b71cb80a504afe38350498e0d178afb38cc356dfdaf55d1e7d723c8ff686df0710c43d9abef9f0f61b91ab3b49f72b96f899159a735"),
    (&[0; 73], "37f5983cd81dd9226afc9deddecc0334e7afbe5957e798c27155a82b364e76573b082159c27f4125f12e81b9fd77f734f43cfe062472726449245be58e93c3bb"),
    (&[0; 74], "37f422a5b2f96bdee7149fca0931122aa6ce75da67f8146a90e948a759e18029e3e665b5b8593d08de8fbcff5aaa4b9d0192e1627c66f58511a363fea5daa0c3"),
    (&[0; 75], "dad31afb6994f62c928b3ebaef7f1802d46000e9f6ec9124cb94f4bf2706682e5438681e7ab7beec1d1d8022f9ce543105bcfa6fcf507185365acd0cd5a14818"),
    (&[0; 76], "f77b0151c12fb8ad595e2b089f3693b7a829182dd2fec037690ed7700e6f3ef0ebb2f69821ba3d8458e8df37ff7654ce6c3d842035297b57b9350f08a28931cc"),
    (&[0; 77], "a32b6078323f303d4fe8ba04a4c38b85bc597bd55a69778c8cbf180aabffa56168224663a826dd64814fb57ffa38c9784c96151fb26ef1e441ebe9e71eadfa91"),
    (&[0; 78], "44ee2d63be79fdd9828d448664e20517c3529489445db0ebd6edb2f917faa12baca5c3144ad8987505288df9389d3759c08aadb3b64cd238b0524ba665ed7332"),
    (&[0; 79], "56e8e55534b585ed88bd8524bb2133898fc6beeb94e7e4465aa2fb99ef56657354b4c1ab5130e36205888dd57087bb7bdce095a82301efdbb6466fb9a8d94372"),
    (&[0; 80], "13cee4afd536f7ed6aa3f7fc90e000504bf01dd041a8a3c1f38f0bfa14258308384b6c5c75d2ab528277de92a0968b6650fcb80687a4eab0dcd87216bc522dc6"),
    (&[0; 81], "887e711da5dc70dd0e8db05e313b7147fba9a60062ec0537fd30066889df1d89c6191530612a1d24998d95953729ac16ca12542117240fa37af7079b0dc58da0"),
    (&[0; 82], "fdcb19402940331c0613fd8a1ea5c375ae37b0fc07321f3d16806283f52b6e6727708da03ffd3e24ebeaf294add17c8c5787f0947464c6e511678c7b12638622"),
    (&[0; 83], "a99c6f678e6bcd1e83e4a401ab6cfe1b1b3554d963417cdac3d26ea8979052677c1128ed75926eff7652dd241eba4d11518999df3fcbce9479fcb37cdc8ea143"),
    (&[0; 84], "9497833b264d9e9098ffbadbb8bab977d039bf5f504a683c2065a89b1c0cdb6d1b03b15efb16acbd9e997b9ab113cfb40652496062c82381677ecef09af010fd"),
    (&[0; 85], "2edd38a67fe1ffd42b597e95610ef6b9aad1bdbf87c1be35656ef707a0bf617ffb7209bd96ef16fd141e0de529c666a529bdb95c881769cb695c5863fd3ade73"),
    (&[0; 86], "4d6b07d4c1232558e2da1c7f2a444447b737f35b377fb1c2082bbf515b15567393a3bd67ee89ff2eae40626417241b3feb00895d7263fdff9f78f6d08eaf00cd"),
    (&[0; 87], "2226a6756a5a160f10c8c3a65b6615a8e77f99f2bea152ed442dd12c6538c39ee2217836deb0d6bb8cca9df0cddd83b3e9e607933f072700a5c149a688f13dfa"),
    (&[0; 88], "55ed019754967a9e1f83f56389805bd1042533f0502d5feab09c945e6ba1557045be4de897c38afcdd729f0ff3d4ede7b3db67f6f20597d1be6574376c2aacb4"),
    (&[0; 89], "70d02f0db62a51c8165667884870e85ba2d21ee45e325b29dacaed80a33383cbc8a4b59285a394de6d8441bde045c2153152d920b9f834dfc6d83296cd46dd51"),
    (&[0; 90], "3c221d9023ad2772a7d3d8795cd69191aabf003a778c45c6b0584b88b14a01213572ab6e1859a562fcec058ac30994cdc369f3d218fde4b52f0322380010607e"),
    (&[0; 91], "834089a50259e664c3c4292f8e1271d5ec1a7df4f83dcae8575088c0dd3a45e65202aa53299d3f3c59d167adbb60040c1c6aea10687ddf6b99bd3067abdeda4d"),
    (&[0; 92], "70710e9ccfea15441ebe35132db133a61f0444852edb9c5fe611a150dcdcc17ff3c03b1a87b2ce5e083ee262901a23417c926303cfc303fced210f7da8b7629f"),
    (&[0; 93], "a628584a87f9c4fc1360a9f5f98529690533dedcbf11490370dd689443ef02959911a83b7531b43373a27771ea32e79ad1b706b7653f89aa5e5ed22f54862ae1"),
    (&[0; 94], "a02939885519b9481f581084f5d32c7b0636ed219b589fceb37d5c941ebb61f8a688bb6073e4394737de9e11f49e42696f15f8f021e03fa67c6b72818a8e0018"),
    (&[0; 95], "117e8007210947f82efbb0b6a0b33a79ac1a35334b80c93763f836225835628190931f5dc065a69d2e7e9e365181ad0228c9895d65f3c4b9fe1eb2fce4f918dd"),
    (&[0; 96], "ec75b4ff82776f103d68d77719299aa08dbcfa46935cd50112926c057d9869eebafe5e1beeb720a840dfb1634807e6fb14c0a9e83f2963c9480ba07e82b2da7d"),
    (&[0; 97], "b577271527391ce52f70b77270d58fe045975736becabc3b3d0f5c119fdb839d155a7a6e9570d40d5fe22a901aaa682aaacc5bba3e6d044f0fcb8261f89504e2"),
    (&[0; 98], "5220181d017485cafeee3ff442b28ce4a30acb5c2ce88169d5de292b1375e2a6f5d4edf4978e001c18d97fdce9a8791f63b599503f7688cb6bae8af90116e144"),
    (&[0; 99], "cf0032a1cefaf29cc8db9d1105e240778c1b886d4735fca2250267603c0466d7208c02bfad744ce1451f651b770552c9a5d8260fb1a47ec2d1089e71540fbfc4"),
    (&[0; 100], "4b0ee2ed4f9f9343720a78e30266cd82aede624aa7605ccdbcbe5ebdcbe794d8dd71986320cbfdf360913844342cdf997bba5fc2272a8c7e61739f7baba76fac"),
    (&[0; 101], "77a6bc98cd0fb9900498f4dd5168946c523fbfd5d31b6a483e0043c0e9bd23c8098feb90915fe2d32c8ecbed38eecfff5ae38890ee7a74eaa692aa196a2102a6"),
    (&[0; 102], "b3275c14fc8ac1f54339b7a02da28e34afc04c5786fc56683dcb04f2bdefb405ed2c0d1614073b74f38d8fa350f62ade8f8d3a046cc94e35699d168fd61c4af9"),
    (&[0; 103], "e4178c9eedaf992c519e93b8614789aec68ab16890230152b37f42b556c3237c3dcd22d499a54b505588384d6739caec0c436d0b3bc2b850123cb91063b64734"),
    (&[0; 104], "e42246db59307b51fbdd9dcdcad2dc9d5b79cc103a24d1d307173bd170cb6797ecdf2d9fc02097acf8a2677bd1c359064383d8ffcc9af94e6cf2d4a55c437984"),
    (&[0; 105], "6996607f7b45907a21e7bea5f7c3db10f3ed9df0e4609a6f58d336ae4f720d411ce71c5af8953c94716c202da5537795d28eedcb890511b1065fb82c37a47f46"),
    (&[0; 106], "d7afdaa85e9e76d77bf1614d9eb8d725f999499e43897acfbb0f988c9b01d2c24f1fd7bc275353882fdeb79ceb9b9ddfc45528dbbd812bae011f9d49088f42d4"),
    (&[0; 107], "2a21d88dd68389a9794b956e22b06bfc24eb26d5435c8dc2c9c9085126969fa959c519a73a1b00ce1365404031e814b432c4f51506f89ce75249a278deb9dde5"),
    (&[0; 108], "d966b3840510aae0f98478e9e4d06329605dbadf60cf224e41a7e391d9e13e5d6001056499482d1bda87cdd986d52972787b1d64629a70c63b8f05842abed147"),
    (&[0; 109], "817a6d7137cf65e9f1c5959d09a8fc7fdafb7cab7d6823a046ee3b03578671001d33b136a6cb744a6c1d9c69400034bb4411dbc3e7e8021ca87892e0f91f077f"),
    (&[0; 110], "b42cae2a37cde36b5153a8f24d4f37ae1a1ce349c38ad1b14fd5071f25169321072d60e1451a68267c91e868f6c37aa5b46ecee06ac1f408d81d973938e449f2"),
    (&[0; 111], "125695c5cc01de48d8b107c101778fc447a55ad3440a17dc153c6c652faecdbf017aed68f4f48826b9dfc413ef8f14ae7dfd8b74a0afcf47b61ce7dcb1058976"),
    (&[0; 112], "aa42836448c9db34e0e45a49f916b54c25c9eefe3f9f65db0c13654bcbd9a938c24251f3bedb7105fa4ea54292ce9ebf5adea15ce530fb71cdf409387a78c6ff"),
    (&[0; 113], "41c57cbf46cd340affe47441982db877083aad641a604fd5a0134b5ddfb63ae779cf38df7b26441d071074a9094baacfda0fb974222ff7d8cd82e42a48b8f69e"),
    (&[0; 114], "b37766e24692111582ca44b77d15d000ac0f043732210daa9a2a2920e24cdd03e526c7ed48cdec236ba52c3d747a837b133416c0c48db228f400f4cb7961d177"),
    (&[0; 115], "1bee3cf5ae02975f081fb04c0134159d67cfe1521a81ceb9b928abf555275b59a500ad57326b5e2b2fa3f7975a9bc56e7766d123e0d97c0f03e7169eda5a9543"),
    (&[0; 116], "ffaf5cf8f3263b8185eb0d2d596678aa7237d5947abf60d76c1cff20369dae34814b1a8496b40efc28f541e729f76d75cc14a44880c589803a265920f41234dc"),
    (&[0; 117], "ae286aed8a3f6745574b6eb321b926a7222d1a7f8069eaa2b49dd4ec1af8cf786515eaefb5c66fea1076997b51ded09fd47bba47cd6d8eb9c29bd3439dca67bb"),
    (&[0; 118], "e9999a9906c977c415f8df9ce39ea3f192f0d1f927cf97074628eb83081fc634edb4129c5e1f4563e661d6b739e089252f47709c784c7dba4e7405844b8268e4"),
    (&[0; 119], "e8aa95d5a3b2040f374a9f41a84e3072030618a7869834cd207d47ab94945ea23b3f8a2e9c0b3ecb3af4f062fb26cd1d685cf9d92d9ba6816c94f66e86c42423"),
    (&[0; 120], "ef29a6a7ffa19f9117605cc280bdb993a7d080932800fce4a3bb0960c0fb7d71135d3f60f1fe3fbdba415448959b964ac6d2d5a849848fe67d615c6c8ad976f7"),
    (&[0; 121], "3c6529f3f21248074a00d683dc7a88ebe4bbe3e971531914bed585bd6361e7dfce64b1f9171da0c07835bd5bc36766f8f3b14374427840b2ba9a42098eb1740a"),
    (&[0; 122], "5e767cc0c0d1504b002e3b7b2e4e5e356206baa024ac12498960069fec6a6ef1439ed20ae3d53538fe2ab17d6cf2b7d5791aaeb37cd495e8ce19f88f6920d094"),
    (&[0; 123], "743c7aa9bcc662db93a516eaaf5274659fb9016ad841b53ff9690c257e7e00264d2be1cd2a6c45dca87401010c6ba6335ca2b42bad47f8e79bbd116aa8ce4d26"),
    (&[0; 124], "268222763afb01f1b07f1474d7bfaf9e82fb12e0a3d1acb12b0df7be0e536d1a7cd12f767903f7ec302eb4baa92be8ba08fa1c224bfc4cd6b4718c9d6e3a3291"),
    (&[0; 125], "4162c8205b9effab8d3bf41e62db01644e9d1efb2e2d7860fe36b2f771a88902caac09fab21ca17d7f01f83825788cdb60b6724b7687a54b0785708164bb85e6"),
    (&[0; 126], "944e4b41f117e15ee81d96b35b40c0b91916a00e47697cb43c3de7cfdc7b9d80f7711f4e42577c03ab773abecdb4e180667ec2515c17fed637dade6e9ee07777"),
    (&[0; 127], "d6bd99cb8f201c5e777f25859cca7b21b4659fce0e19d04de85be6566cae87b9b15e4b82f9e80eea894aaaea15e26f08ce6cd2af9f0fef1a15486cdf9c8ca8df"),
    (&[0; 128], "0f6f3a3a91f752d37e3d37141d5459aca9a88ed2d5b88f71120fbe39387b635ecf6402a5bcb7b18f216ea9a8137d28954098e586014c4d435c979d8860d3a977"),
    (&[0; 129], "c75df1083f0cff9a4b423b0f5cdcee6526133513198f897c89901d0ab80995bf9cefe01c992563b5dd4a8f76f22f16859615c30b309efe329f7462eb280df34c"),
    (&[0; 130], "c17464a924063439e5c8982956c49187e1835a73c2e2931ac28071cfeb27799fa138716da6a9d138115bc91563c1c217f6fdab66bdb635a1e78fb835b0f9a609"),
    (&[0; 131], "82844f51a78951c63232782fc5d047ad2815148a11309facb92255f586c413e3bae2a593af767bcb8450448c94b45f80f4152df9865e7f7f69a18aa42b4dd6bd"),
    (&[0; 132], "1c7a401cf94195ba8f21e48ec612438c453b53c805ae31bae9c49f86fdf7138eb8d6fd132d96575bc786cd9d6cd20e31b3735ae297c580ff0b82e66804264b82"),
    (&[0; 133], "57f6a984767dd9844c0cf1b127fc8d0a5d675ce09c2f98890de3bad2da3fe73d6f23025ca4cb8c8d2c09e887a1b1f93bba458858c381bce316b391872aa939dc"),
    (&[0; 134], "7d93168eefa0a4c29dc0f0f469701c8f0cb52b1417a383cba7b161ef1896c3280f5a1da56eeb7b20b3fbda668cf7ef6d3c3a7db511df49b6d28012b803904bfe"),
    (&[0; 135], "64cefa16d8bb2701ce8adf301a1036f785ff85cc87d149e60d8948b07c180943cddf5c85dd20783a68c46954d03eb3bd88815593061931ade8852b690f0516c8"),
    (&[0; 136], "97b3741dfac771e8ff95f94d2a33ab224341ccb0f5dee1afea7e05f73737529775e8130ea30bf2550845403849835e0ed69a37dae71bec95a174ae5ab80fb280"),
    (&[0; 137], "114f40a294c72807b0870866e6ff2fa1972ab3980e8233092350753775897e8444b21264dc232ff39663c340807fc72cbf11d1259532ac18ade45aece4246899"),
    (&[0; 138], "f12ec00dc764198d2d2a3e6848805dd8c262e4d9ed1bc42457a4268d19973c44a1c925a792dad49e3d148f732e68bcfbaafba8d1fb2e57894cfc2d669cd5004f"),
    (&[0; 139], "4270f51b5b6fbb0af5def1df5223de7f5e8752e80ec1f283ab0e146a59a2ed182ca1ac229a7a12d69c46ede8d2d2bd3c024013fb87cd51fcbc2ab9136f32f77c"),
    (&[0; 140], "071a521772248ff1e2ad3386114a21ad3d393b293719d3ccb5e2470bab771b45b9f369d580bd4e08c2d55a1768ac62470f41b32e8167eb95401460fc426c0906"),
    (&[0; 141], "30e10ab2bbc72a58a4ce00720f6af9e917d08aa17a86df8b3033847fdc5686e38276682b335399a808e387e3e1dfb89327262eacf7db526a30d3f5b5338b5381"),
    (&[0; 142], "2d83ac5b6c9b8db2765d92d7be4d6c8586af4d12a375292c011bf9ef765bb774005f13f3d54aec85110e35460d0adb871f7351e75d54a6ddb79b601b0794bfb0"),
    (&[0; 143], "4f3e28a4f19fd7afc1f1bb2c72649635a4816152b6c94ba52d0d168ec7ab4a0581ed10db789acf9ff8599ed6206711bfd8d593486535c8f56984fe0343f44748"),
    (&[0; 144], "313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde"),
    (&[0; 145], "b254464ff19dc7ed5cc2f303cb259f3e97714baf850c35f87e71e45c61c2857f9eba4c6df0c72cc88d4db35f64bd37d7af6d292def860e46e214ecaecaa9273b"),
    (&[0; 146], "c43c0438d426c22ed6ced56dc7113eac74e95f5783bd40681abbad74fe0a8e76358cd442ac3b610a2762d6099b05e31a160fde53d77c1b6eac03b3b729fba2f4"),
    (&[0; 147], "1ce9054be2d182b7d8945eecb48997870a863671daaca863b47a4394ce5b117183ff363866ebca6ae8d99ca63cf36d57917db0be89213e388927fb2101671d8b"),
    (&[0; 148], "176be8c6a83eb355112ba58347c0f92d2f1b6ada32d84d8316bd5bef984a4c9721c462d71cf0556ade14494a2269d60ebc6bb286c784f44e18cfec747da878a0"),
    (&[0; 149], "e811fbda32382ceca2575841d21cc578faafc6b4c72f31d0f86f76c41582d25ee822d8c00296207ee803c4a9b40cb6b3602735f91a6ca3b508d0592d37721255"),
    (&[0; 150], "8a17006e208ecc936b1334deb828b21006effb910311e2b367bd113870200cb07bcce4b5b79b6e85184465fe9e58e5eb8610b314e6bb47ba94a15a52449d0b1c"),
    (&[0; 151], "ae1a9207ba42aeeaebd208038d8bcd4671a683dc7c219d807d4eb8807953321c62ec7f745382b4e6dd306667bcd418c39e6a5bd056158cfb5adbdc6d75034f34"),
    (&[0; 152], "c204c0c7c54152518289062ff0590aeb8e01d16f3a41bba98f94dbbe3926cc2402a4e7ececec5b392737fd086105484d7c39b269f4f84d26fc782e12c2680c42"),
    (&[0; 153], "8a9d14e48d56415f20be3d644f0457e9eed5e20ff2c5ea97bce8fa3baf4bf6b18b1b75645281e458a1aa165ea13bb216b3a268e3510cbfb0accd6e12f498e0aa"),
    (&[0; 154], "11caadf2ebaad8e9cbdd5e90c3c2d03118988647c9d900018995527dbec374dc9eeebc29c55cf1f8c064dcd3ef13f887cd3e9074396f9c2042969abb81c39726"),
    (&[0; 155], "ee9fc505643be9de46b9a60acb37e8e36a01dd2a8277807d1ca2d9521147457cd1a532631da9461880b51813db55e464a94239cd40fd4f6222c7c66bbdefed46"),
    (&[0; 156], "35e1ad1532a1326cb1ecdce6e25c25e13e3b2ec20a7b477a069c4db0bb35efc759ffc6f84eca2676e238e78b896cd102e0aed741399d3aeecd6688cb4b6df73f"),
    (&[0; 157], "8428e6f91e28b021403b913fd4f6a6340bd4307940e0f3908c64d57c01bb2ea90bcd3c687460b49bb030fad49c7daa6abebdf3989f5f9ba07d05629eba5e02c2"),
    (&[0; 158], "fc74fe57a7235432eae85ebb10d9481040abc6b8cbbb16974cba196fee6836b563a14d22c2f6eaa0fb850e107e356e4ed7d2d9c109d6f0b26c115c2b4bdacc5f"),
    (&[0; 159], "7fafca00cbdf3d0a67d6b05c2dbf554a08885af30144b3a45ea285bab82646f950ac1743df3b5bff43835dbf7af292846e436c6de588c03ae27aad940d20c78e"),
    (&[0; 160], "46577559f147aefa3de3686c1b2a1baf7e774be59c2016f72f6af25ce9baff4a4d6cf0773a80b6b70aade86ea076547c70416d56ff9271820681d0fb0de1ecbc"),
    (&[0; 161], "3b2afc8428293c8a61152fa25406c4f62d03952022b9f916ea17886bb9bc9c6b72483cf8a89f13bf835568e1054af10d65ad501cc935dfbbe802fad6431e2756"),
    (&[0; 162], "1b51e697ab79ec875821ca2c903552b034fdbee0dd4eded566adf071d0dd574c858c49a0eb6a29a0c1c08a8d39cd01fadc5ea0b463b5cb5ffbb049aa5da761ea"),
    (&[0; 163], "60e2e446f8fd66e88327204182c1b9c34b720ba31885c7059d2569bb5c71b7b4ebf03202e5cf091c78a45783240af49785e47fed35b0ae9bc4ebbe2f8531ed89"),
    (&[0; 164], "a893e5ca9305c9e76a7a06ae0f3d440064eabc7ad1cc32065ad918231c407e3ecd6c52046783110db6ff9456d48ed311005ce5c4a7b554981a2efdc3317d9335"),
    (&[0; 165], "974fc7c6859008da5fe9df658c2c4383564711934e154a2b4f7c7c9ed23649fd5dadcee9be8eddb84f9a92f46c9b80f6c3d9edc3efe744ea90dc43dfd5559513"),
    (&[0; 166], "6494c40dc2901aaa12e5bab6a2911e9ed6e0c0e294214d0256ae9d147a068958329409dba4cc5f749ea6f7e13f3e0872ffcd2270a1d7a80ddb10fffb3e77cc84"),
    (&[0; 167], "bce42375580c37c05aea8c394fb51462f305d7b952b51bcfa0b1874ab0364c95f777ef1a7ee4bb6091015551a0989a8efe6fd3fd4b212f380210bd12b746d677"),
    (&[0; 168], "7458dc44630ac77f6f85c6c7018563a4d130033eda82815e1847d30cd0d4a1fbccfe2976ea3a01b9609bdc1a6622c00e627e576b655e1a9bbaa732b61e88c0d7"),
    (&[0; 169], "36f20ffd44623a0d9db18ab387b15c7dab8c17db8428833533389b0d530e3cc10f2b1aa5480f77b1694e227942b13be459952558f5ad26affbdd1d72ffd4ef95"),
    (&[0; 170], "41c614c462f1196f7172e3b085128ad35a218ad9a84c3a4943d6a881381f40609616b837b58f5c75f425aee1d8447ad9f2f7dfcadb4b40a3e99699cb1f988d61"),
    (&[0; 171], "d5c43659a6ee7518f20cb26331b221790f21a1cdbbfbb7955be91ef298d59bee7ef8769c5fee20dfbb39529d6b7bc9070037dc928aee3e8bd20368e933598182"),
    (&[0; 172], "afaac726c9f98c002d2b20ffbf03eb3dd0db9f98231014ae97078325cde86107f96efd506ddbd3f625def25a53e68f31a6a393a7ba2dc26f468c88e1c0c70dbf"),
    (&[0; 173], "783978f6bac55dc72491b4f96e584e55c0626423311e80ad70027be8a723b29e3efd8786272e84f11ef37d1c56216a6c2b01014965a297920da264cd878a23fb"),
    (&[0; 174], "94f50c046e0877fb8893fa12fc9f044e9cbb9e0cba74e0ad19e7266508b376abbcfb22fcee2e3006718cc23a573422d60065771eef00909cd3efaf2a2ae33b65"),
    (&[0; 175], "dee8f2717636c5467ee94cfd9db104c7a263d4855c4d978a530a8e41fbedf3c4482205d267eaabc01019c215f8de99c825fe96232716344f98a648e28d6441ea"),
    (&[0; 176], "c82ccbcad3a3ddd5d5ec13cb7371b6b5be7c2456b0fe3e75080db3bf0c56fdf2b4095b24a266466f40f4dc986abd3fe4e6185b3e478edaa7e2a786b007a39c65"),
    (&[0; 177], "8eec166e72ba418814a827b8f771b95ca1dcd9c43d3d908e5cad474273ed4b148ef44d3e96d6ce59abeff5e8dc5d24d97c7d3fce539ce4376cadab86bdfda2eb"),
    (&[0; 178], "0eb628a4e66cf7c246eb4cea31cc23ed4294f2a8469165091ac1e09cda8153a9fbd4fcef93d6f1dcf126a95c5dd49c234d0394c001844c54f74466d71f458a6c"),
    (&[0; 179], "d4c76da700ecef89ec2114f1a46fdbab2452d5354eafb1cf14cb06c16c4aa21372b7c85a5e68178468952c616141d80876e72e67755c08c03122dba1e4965bcd"),
    (&[0; 180], "db8c0ad8b383dd8434557d586e5c40e3ffff3a7020b646b4231e2af69326a5d24018ee19cd9a987b35cf258f6ce1ce22ec2387606fd94166222f3502ce3f038f"),
    (&[0; 181], "c5708cee8d6ea9a67246ef5cd11035404483acc21b1188cf60826e73f5b74c49c13c83c9660cfd78ca553087535e1635d079fcb3a09c4f0297d4027db82089fa"),
    (&[0; 182], "9564a7886d30e4dc4903f6cb3ac621a39fe252c3f42bb7bb4ee3fac5b3cba25ca4f237caefc4bafcf013121e09f478c3607b60103aeae76595ba151f7c4904e6"),
    (&[0; 183], "ceb66d299edc394bea8618d7c2cabbba77b882a3d00836679c21b9f2663779842fb36d28acc233035366de025761145cd30452cf535764542840ba2660fd9bae"),
    (&[0; 184], "d6f2d3ccef5258eaf592181c82aaca9d6d49c3f243d5c026dd9e1d216b4292a378c0400f018759ac57c9a6861439edb1cb501339f67c4cee4bd94df5833210cf"),
    (&[0; 185], "d46ea04cfe190f139c8131ca88241ad7e4a126a72feb395e5d1a602acbac314f2578274bb52b019e0c1eeb72f8bd9fda3994145751b8343f07a97e8720aac723"),
    (&[0; 186], "ed8fd3f57e09b7b6ca8718ad676c056cc4d3f1c0caf03eb29897b4bd23846dc0f79ab10171c0905089a0272e7af1748e2543eff40f29985e98c4049dfb11ee52"),
    (&[0; 187], "ef73498633c1fd57036e354c0a8363db578cfab94d23766324d242e198d2f8b6e113c29e7eac9d4a6e246712b35cc262ae868886d74ae1313b27473e958b14eb"),
    (&[0; 188], "de75f34963e5752b696e640e423aab997508d55b80ae1eddfc10e66179b2890423702c3d2c6baabf1b7e393bb6463614b476389246e5b815bb94dd2495772ce1"),
    (&[0; 189], "967ba58cc3302f5fc4341492e5469b37b3c133ff54f830a71ee70f2e1b7baeff7a0eeaeabf61cfa9a7ace1b16407849cf2a865b88494f91a98caf8cf66374e0d"),
    (&[0; 190], "a0f6e6b49033fed39e23310d3c531ead5297c957d1274f260e151c38de7122ca172a7523d7d078d98a25aafbd0aefb3412dc01a7c1677160324645c3c5d21128"),
    (&[0; 191], "7bdf2c6ab50cf34eb320a377165a854b20fff479a5f63f209288bfd84686470f8bf2f7d89b88bb6d95d4309855afaf8b95c74e6b65e3d3a4b513f7a47b245a48"),
    (&[0; 192], "739c3919b5e247b76f2f3d88be82842ed0eaadff6280b18128c489bc356bfc7fca3abe99d6680a6c1ae95f63a2d044b770069825b7acbd887997b48817736c3c"),
    (&[0; 193], "2d1201427acbc4cdd9093e3f24c74a8b36f9b762ed1ccf8bae8b52700faa9581c93cad2f5758e34599e206a5eecf4f331c2015ca743ea1fc49b17a53f08b9490"),
    (&[0; 194], "90c6efbc53700474ae4d79f3f3c7e6f333973e6e7aee72af1ecb76a4b42736be5ba1abba8cafa7d1c58d15d8e77086d10ebe654784ea7f00b37909d76f578e69"),
    (&[0; 195], "4c4dcc1f6a910a1aea4b93a65cf9eef30db1a59822ea3519880f426d0cfd09edb850859028cbadc0e13a9e7d6814afc12e7d27607aa1869824888be9ce4a2e63"),
    (&[0; 196], "1aa51dad3ba2b8a730d6f3dc3c2d003da93aa6356aa07ac428efd33986f2cf6c19a9cd4b697b1843a5b75286dea98d20601c80aaeee0791f09f899b908281edd"),
    (&[0; 197], "5a908d76d0588a8c924ccaec3a5dcada9db0cbe92726eddb3c27915998100b7fa5c211b446fcd3c196947a870a6ef0c509920c81df7697a040874c509374d086"),
    (&[0; 198], "b9eaf5a1a1d4c9ca76e10fb1abe11677a7c55b58ebf7d3a6ddd6f632f45c133ef8a24a4126b794ec5315fd4af67ebf3946b6bc3ed595bcabd277dba6851a5083"),
    (&[0; 199], "bb72288221a3dbea87ff7404f840f5c988c7e1c79f3d0df58ba198e1f994f8bfd839c696787f21dd0727d75d5b6f5079bf4ad068b6aecf596acc9f59a4e60228"),
    (&[0; 200], "e7026cb2fc4e25fec5179cb40a2565597ee683094a7fabd370c13d1ca1ee70b685644e86c26662fc031ba2e7240f1e277a55f4fae70669ed5017247db3549b4a"),
    (&[0; 201], "3642a376c5645154cdbe2fa3659e3cff0aa5db6be423952c5ec5a20d3f5cf70fbafc288e85a342a01165d03d63bed4736c092ce68617411efd26a3f33cb9fa9f"),
    (&[0; 202], "0f5127464d0d7677b579ca1bbeb2e15d1ea0eaa90c5fff72b45dbf322228dea479d9a4add54193ac47d45964aec6fb353145d0ec6e302e4d7761dc46cbde0eb5"),
    (&[0; 203], "ae35741aad57641038119ccbdd3ef33595a88a49a5c8f17098da96e66cb1bd62d5cc11b2e526ac1f4ffe05d61c76c34e9fa64a0af75efffc4038f4dfc9f2f29d"),
    (&[0; 204], "b0ffe2435051827ac8df836c695d3ad761d9530340d81cc499775bd56d1870e235e1a1539b002cbeca9da42e226cd14a5324d4bd978e780863095b51ede4225e"),
    (&[0; 205], "b0ed43ce64bc54ccd539aabade5b380263b4b3f3d5512a80f2a955660877dbce9ad2f3548c13ac01ee505003d057b69c2d4a758b62e46fbb82d87ddc0cf0f7ea"),
    (&[0; 206], "5f42f68e2610e0d1183cd866519ff4f507063b22e06dd8f9c1ac5893d894ed776c7f6a89637580196aa035596af030d0cb631a3c13441bb750d854cdb68f7c06"),
    (&[0; 207], "d7cd218e44bb988cd7fe7d31d66a06ddbd10ff4536498ccab9c7c9f5b9070b5df398f7fd849f2cc983cf4527b020c3e20b2d26f626c917ab3b6273d4a3031abc"),
    (&[0; 208], "ec40228eb4c903255666d2baed6d297b0581857722d24905e2dad42c7c3101e9b55422d058dd20e8adfa6e49216c17c8735727e010e1ddcb6521ef1d3c831d64"),
    (&[0; 209], "17add424edd2415a4fe0bd73d395a3325fce1f1243bfda409535af2554164ff3601ea35c6d7cb09a64ad35e8d7a632084945b615b71ef23a5cbe18dc386c8dcd"),
    (&[0; 210], "1e57a3a7f9a0b0d360cbb1ef35f781db02261b2cb59f4254c9a8eeda51ebeaa5f13411075fdf4e5e1e3b13204005e0a3a73848b7582a29e71c44a07e5b6fdf63"),
    (&[0; 211], "2cae78383486e5bdb4757f50bb261e3a7a3f6250dea5919a718dd2499af5546b3b85fb4946af981525c1754b2d2ab2ddfa186e1fbc75b2089ef6294ea363d383"),
    (&[0; 212], "e8bd03f0b89b5a0643cc8eaa1f6ff7435a044cc4304ba24adccf8229bbc4fc598d0c45890460a18bcae592320f05d7859ad2e9c03290c40dd8625f89459bdf80"),
    (&[0; 213], "0d6e5f11e335a4183f50adc9877fd00a646b2356d8e5d37f85a6eb5d5dcdd050217dfe4788172e80ba1e92c07728650b7de236bdb3950bdb8caa442ac0779040"),
    (&[0; 214], "9e70f463ee83f954e19e48b3318f493775e3b3aa23c2b4b1fa26d030f375b87e6bede9604de71373d9eaf7257248dbb65088c30a8f3ced4ec30b67ecfbf869c3"),
    (&[0; 215], "626dfe752cb9e4851fa6f55c175f2c951c16fb0cf68e664128cdf08330c816e25e41400a56477e75092f74b587206fe705bc9122179224c23d41d7b93fa04599"),
    (&[0; 216], "b93b3e1a73de33ef32f2608e6df6e551970f521ed73fe93f84857863acda8f8440bee104787a01c308b2ecc66e3ea7e427ed8af919a0ab6efe5f8f805db11543"),
    (&[0; 217], "93b2bff47626a6afc3bfebe623584cb57cc37da4d0e3c80524b06e02952d8ea77166df0352c14893f0f65cbfcc4551151fdf0c11008de4eb5e20ef1293281060"),
    (&[0; 218], "cd25ef89c745ff4f10a604340f548c3cf9fbf81c2054bb66db66e4eb4734354d5cf7d4b2f280b2ca38d52621629cfc770d147f32a4b4ef1731339f375e222e12"),
    (&[0; 219], "66edf9d8dccacf1149794e90889ff41cbe6e7c5c59d1dc19f8671e92831535ba485bf239a4d3a2521bb0fd342d0a0db8120fd761cc5b239fa877aa293162947e"),
    (&[0; 220], "e811ce78e1f538394deb3c562bd1de03f92e510ece658d20d43695e790b2e0bedab8ed363c8bc4dc7640b08172b5adbb05276862e989d21c5701e2d719c10e61"),
    (&[0; 221], "08bedb68ccf512f6844f5b37d8ceda4508443d598e126f37e4affb757c8e284a9cae2d44162bf6a2fc2d3194caeff3f60cd8cc4ee4ef8065e9db86866e9e3b1e"),
    (&[0; 222], "e0c1860d6742b157d170da0ac7e05f810f0ddda8552c335ac0849b59c4d53f82dae4794a2b7a101580feb3ea2c7c3ee166b58c87ff0564693baf3c31144fc091"),
    (&[0; 223], "955864be5b15b946e1f3f0e2dd91ff5e4417790f8b75dde3657862a44ab46b31762f7e09eda9c4073244fc7ea59c72e45efc97f3b4fa339052f3dd3b1050d1f9"),
    (&[0; 224], "869f27c8d2394b6de7438795d25441e06713022e2882b4e3318437c0159cda90b52d839e2997f44d3bd1c48be3cbaa693710752fdea81ecd26c9d4b67bd3a716"),
    (&[0; 225], "3846fa90d344cb14d20392474ee7d200d62f7f6b1ae3fa3e24665dbe8713bf6ff67b54778deb73356d49f812a245d8f7280c6a7318116be63ba2b73c3fcb3662"),
    (&[0; 226], "23727674d593778bb3953a9147a847070635dc15bca024be5b177d33147ce0c09e7a8c66f513b2a0a2ed8b97dce7ea21da8c797808b821706067741cfb92cb87"),
    (&[0; 227], "602e90a0adc4ec07c1e9a8da6243ad4e8c71c1c457c79366d2c918b158cf7a3c263db7b804a378939299f6236a9f19f2ad6bc289d786238a735fd1636350939e"),
    (&[0; 228], "4b912a8714f39135d5ff26d4d880d8cbd959195a56f1527e72428e5184a37cff0c45d472a5b81bb2764c1379afe300e6a04a693691745b943d603512ae4228b8"),
    (&[0; 229], "580e993a941c1221674e9b113cd636126f575d43013490c5e906b58928ed4f7e9890f0868a3bfb207071a4bdbfb4e9c463a108dd42bb38c20509b27e2b4685be"),
    (&[0; 230], "588adceb5dbada9d9beb0d31c006bc79ef2e1fb99ba1884052cfd8b38566dd91c7b6cca484733f1699249ff9b6b1277f1661b4618af5ec7c6d592717ccc0d9a0"),
    (&[0; 231], "0d8815b2b0cd2b10a31bcbcf6c45cab344caebd2e311eb4f275c9cc6e538b353a001cc840440a2d0eae64a29b022cf62a854bab23a3ed4000e6741a81dd52435"),
    (&[0; 232], "599c9d20be8a8218f0e4bc00d3f46d9a7687b774ed73ae5dcf0db4b83b9233fc658e7c389461b81525d86e97608fe9fb70917d96f82096f0ab8c906cfbca8867"),
    (&[0; 233], "b9ea392c17f1dbd8a839be0689a76918947e47249d11a1f58298280b2daa2ac7b8c50593f8395aa9cf63249e45c33f91a9f72e5f5830d2540e11bc0ec760f6e5"),
    (&[0; 234], "2687c9d2fa8c0ff4612e02ab3357dfa2e983416353a2913c4de4d82c5fd8833075015896457b33c3b4ba63c8e97f48c2f06828892b3d2f3cf52deb5d0d73487f"),
    (&[0; 235], "d67b0926606c3dfb01e65b10a0328a0abcc655b959e8d2af5a5d339a102dda320edff101bf63f461eb1a3d8c9253dfbf465e0611dc7736e666c3d7c6251f8e07"),
    (&[0; 236], "9b898521d06cf0eb2ce38c691b49c7e5c2f58b959bd62ad558f2fb262d69b81e15eaf3e1b74abaae0ec73a0ccf1ead6b500a9298b2724b28573024018e5770ee"),
    (&[0; 237], "7630e98dcbe7540e150f7f22ba17be72563896b005391bf5c162d0365f6ba6915a4920241805ff4b8218ae9410820a9aaeb807fc0ce410c9aa7e2a5a373d4f37"),
    (&[0; 238], "ffb7ff1bcee9eefcafc6d5134608ab35a7cd48614c7302a213d716b252f9d37d35cbacf77be36ade818e2a666c8adce998e7df07ce45cf6ebcb2ef9a2b813920"),
    (&[0; 239], "0f7bfb0df7a9e8519cc9fce93badc71edfee74b39b8d142c42c2fb5244b3402f17160c7c9184d1fd1688c3fc5ec5ddbf785d4ff8dc0c2a28798375d5404aba29"),
    (&[0; 240], "638d5f35b931eadfd47e0cbace1fc2bae7ed492c7b77e544d9558f899c24bbe327cc8cb1d558120147381cf20afe87902f6b3479198c99fd5408e91f823e88c5"),
    (&[0; 241], "ebf573117efd672260655101943f975066a5b0863a358c3fa98c80bc0ade502b21820d99f35b0adb62f73cfc7d975bdb7d7453c500ad83f9e5bbf5222134bd7a"),
    (&[0; 242], "afa0294465e603f1f8f2be377408b360ab63377101203b55182fef0185c7cdaaba428f7f41a800fd578cd83ec4efafe1df819c23b952749ec54f07dc4b34d21e"),
    (&[0; 243], "8d9bc1bc3154c70d4d9d9771e0433b483f7ae8f41edffc24e2587d6b3381b8127a34d913345b289d4cad0d9cc4297441c1af67e76248e51e0fe1063cdf08167c"),
    (&[0; 244], "94a88fe0c0ce6c16eb60c9cb3630c9c6fc22be362ea460e16f652e76626c14722f65387c77f4342c685aae8a6c9a6273c7ac1a75241beb3f95fa2b9794692462"),
    (&[0; 245], "695ef6b1bf8bbeb94c204f72b296bb5ca3451b853b441f453038856c680dbf48973478bcc12bb8c21c41b5cff835e8637dddeb389e8e160f0e2c9e86e1410b2a"),
    (&[0; 246], "d906bf4b49945b52020077270442e79e7f0a4283d2ef0161c4ff9cf01696c624463eff919d7c297209da959ee0c81b60924981f6f4ab23e58ad36678ae3d7037"),
    (&[0; 247], "e046c398a348561f5317781a55ca7afaa6c0d6564d4d53406c842c7c3f3ca1a984ba3d390bb844e85896999f5ac7aa19fe0f01fe40ee44f44b22355569557764"),
    (&[0; 248], "418d9d3d4736144ad34a76b4136ec693721ba0637e0a345a2c8d47595323545c72fbc80d2fe924b2d6723b3d5f41fb30d397d9a28335899b4bb2ef7e113bea88"),
    (&[0; 249], "fe978280299eb601759b83fa3d989e3e18552fb0769e12bc5e6a856bbcd53f2d2423c0827dc52af2cf61eacccb21f5e47d47e677baef3189f8106e05c6115669"),
    (&[0; 250], "e9ca9fe7db4846a4aacbb9d6773235d34089121ccd94c33ca22c9d53d54cf2a33defd6548e18355271d53403b2f42979b76a147b8a9800e9c1acc31f5092a9aa"),
    (&[0; 251], "536a8d343e71d37904f724a1add99881e2ac9311ef777e97d8ff75eb0e1a26f9b7688cb322be51280f267913e8389b9274208f07bc7211e061be08e336d27ffc"),
    (&[0; 252], "0d2be3dc944eeddc971e9fba81f88c3dda11ec4294db9a275401b7b97e14f2afe72a634de1834430c3b19b6bb96f365016056ed4cbea00593705ccb3392741a6"),
    (&[0; 253], "f728493e6bd518fc7ab20ed07ae6c04a1dd75c5ba1c891b79d91b2e071026612af90edc718d4008171be757588305d0adad578fe8853d30f61f78d1dbf379527"),
    (&[0; 254], "bf809713c6c48ec510447ad8cf768b4ecd3636f20c8a4c07b0ddc609712519792126a43c9f4a0c1fb27d7cf6301d96839cc39087ddf555f96f4e63e89c0abc13"),
    (&[0; 255], "1406659a0c230890c6f5336d24132d9cf4f7de4196a7fe904a196d066a1156df2fffbe5bd8bbe05dd2ab2cb1ccb4184440160fee0eda0fe292adaafa83b76f35"),
];

#[cfg(test)]
impl_test!(Blake512);
