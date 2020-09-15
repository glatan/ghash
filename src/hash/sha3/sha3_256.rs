// https://keccak.team/keccak_specs_summary.html
// SHA3-256: [r=1088, c=512, d(suffix)=0x06]

use crate::hash::keccak::Keccak;
use crate::hash::Hash;

pub struct Sha3_256(Keccak);

impl Sha3_256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self(Keccak::new(1088, 512, 256))
    }
}

impl Hash for Sha3_256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x06);
        self.0.keccak()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
#[rustfmt::skip]
const DEFAULT_TEST_CASES: [(&[u8], &str); (1088 / 8) * 2] = [
    // Generated by using XKCP(https://github.com/XKCP/XKCP)
    (&[0; 0], "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (&[0; 1], "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"),
    (&[0; 2], "762ba6a3d9312bf3e6dc71e74f34208e889fc44e6ff400724deecfeda7d5b3ce"),
    (&[0; 3], "4f808a691382f10c81d6bbad4a2016bf155f36623197b97e3bb47afec194cead"),
    (&[0; 4], "8b0a2385d83c8bf7be27e59996f7d881d3bf1fc6606f81ce600b753ad94192a2"),
    (&[0; 5], "67702a0ed25a50c46fc0a0fb46a6dfbf5333c9dc25451abdb1eeac93f1e968d5"),
    (&[0; 6], "c1545e05e6777d834652396ad104e7e971a78d084a9b9df34f7a16fd493bf2b0"),
    (&[0; 7], "39e746dc19f9ee593d9f5b776c8f08bac2181c6375a21522cd99149f4260bbd9"),
    (&[0; 8], "48dda5bbe9171a6656206ec56c595c5834b6cf38c5fe71bcb44fe43833aee9df"),
    (&[0; 9], "a8d09c0cea22ae3e1d85788ed488e3b16d32bf23f1e9c2566d83bfdb792cc12f"),
    (&[0; 10], "0cd5285ba8524fe42ac8f0076de9135d056132a9996213ae1c0f1420c908418b"),
    (&[0; 11], "8aca52847e66b1ed300b1465a9a253f9f74f2cf6df3c88c9caee389fea2d5ace"),
    (&[0; 12], "c209c3693abab61dede95d1258a7110636139b3b1825f9f1781d1aeab75f282c"),
    (&[0; 13], "1bd8d70167d2e5dd48897626bb2f054ba9326fb9d34e983b251f62476cd3ba93"),
    (&[0; 14], "34dd7978af40df9b69dfbf9c40f5505c02c571e13f4e1a4faba1e7c5377546a3"),
    (&[0; 15], "e66d1e5fa37fdd234580eddf9f48bcde4ec4a0b17ea752fbab9dca35af244b44"),
    (&[0; 16], "61664696888a110278ff672620c85217e69aa662a83304052f1014d395f545bf"),
    (&[0; 17], "bdd1dd30c21c5981ee06582fd5234b70a24990af7bc554c5cdac42c0eef1dffe"),
    (&[0; 18], "d6c230fa96cd2a2aadb99196a84aaf736960dbb723ed091e9ef9a45b4c788c96"),
    (&[0; 19], "585a09a1964b61b11a8807d2725283ad09614764679ee92b41fcc04557050e29"),
    (&[0; 20], "f3683c9e3da9a7f90397767215345efe3be07565f14ab80d102f50644b98fbfa"),
    (&[0; 21], "e32a0857cae2af23157a707c288e8868ac085324c8681f6b8a4665979c6a071e"),
    (&[0; 22], "261ba2959b6abbc6d419b9837a17b463c571b02982a9c7a5f265858ea4f7f54c"),
    (&[0; 23], "fec57e50534e196e472abdc203f6924bdddb6b1fddfba09fee7e4d6d15f9d617"),
    (&[0; 24], "dd65132c50b1b0b6d6f2ee368ef4b1446ab4b06e9cd5d9769bf4150196f19e58"),
    (&[0; 25], "135c08338f2b90c773768e3f14c7f1309d4e2b1d06beff1f5c98083b2419c54f"),
    (&[0; 26], "fa3aad8e5fe998fa3114395752dc1de93ad48667177477ec881e190622760732"),
    (&[0; 27], "028744e3ccc696c129422b79f8175118c0a1b32e490a0e7f757820fb534f8a45"),
    (&[0; 28], "d76fce0472f7c0ff55c43802a2ca6182392d99a238a25e6ae5c6fecac449f425"),
    (&[0; 29], "5ebacbf7fcd119cb8a9ccb38db43bc2d6c5b763d5707151297c79f275ee731ed"),
    (&[0; 30], "763cbbc3750144fa147bb5cfdf0185bef7d0ade617410b81d839432ebcaee9ca"),
    (&[0; 31], "577e6f36c6b80893aea7ac1892b189a1b988672ba746225b26172cb6e6692919"),
    (&[0; 32], "9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e"),
    (&[0; 33], "dc33296e4d20f0ef35ff9fd449e23ebbaa5a049a17779db3c2fe194b499aaf74"),
    (&[0; 34], "7b8f2bd58baea4bd5b7a3da6b659b65aa1eaf5e6308428e9dcf989cdcc97bed5"),
    (&[0; 35], "d9d257253df76449b66b8ecb035a90df05b7746d82317a18626c6d591c76bfd5"),
    (&[0; 36], "372d46c3ada9f897c74d349bbfe0e450c798167c9f580f8daf85def57e96c3ea"),
    (&[0; 37], "f6a94eb25af430f190ef12ed33fa4e1d95a8fcb690b14e633d3d086b847db716"),
    (&[0; 38], "13a124f6f9b1f7a9c7fa00fbce0afa27d87b3cf09b2020deb81d7cb2a86bd0f3"),
    (&[0; 39], "c888f9b5e1e98013eae9a681212a9523317797bffc7a2c118c55dc183e8799a5"),
    (&[0; 40], "fdc6d587c83a348e456b034e1e0c31e9a7e1a3aa66ea28a759f0472282631421"),
    (&[0; 41], "8ed86dcace44f8338c33721c084781808fdebe238ffacc94676e1d4b471fc440"),
    (&[0; 42], "729e62ace660b283ddd5b0ecc9805db459a3375c8e0a2a3b80274d24bdd9142c"),
    (&[0; 43], "c4c1425191bdcc5cb2df89fbcd7da6e4ab6317a0943902af3ab1281f87aa7310"),
    (&[0; 44], "06f473f00da7697c044c5aa385e710964c2e9c13c1df53a720258ce186ceecd7"),
    (&[0; 45], "98ae4e8a879690d44b24493d3404d622f4e31c25ddef2e5b3da12f4426e46d98"),
    (&[0; 46], "8e66ccda90691c0978c0d48f5f5a0983d9bac61b9b78af36a2bbd7a3cfe111bc"),
    (&[0; 47], "fadd36d690b35c251189dfb755133f7ebd83a2b69470e60e6e07857f8f6f955e"),
    (&[0; 48], "85c65d13c8719b9f883fe61d15ada028a9193d55cb4f2bb605ec8d7c2ec1dfff"),
    (&[0; 49], "c52c53708767e2146de5f43a1c4a03c2cd297894878684ed213d2b4b9c904cb0"),
    (&[0; 50], "8b11da7e15a45172e88775fbdcb8b6fd2e0cd274c604775a5ea8eece72aa8ec0"),
    (&[0; 51], "33e9de6349aea0a2e7fb10c0ae5c2c343d586db439312ef5ba9647dc3f0e8557"),
    (&[0; 52], "c61d8920e8cf69c388bc2ff68105714dd07012ff5772a76a189ddcbdbf5736b8"),
    (&[0; 53], "572738108d102a8ecdc55bfaf298118a07b4bac1c27c2426227f3b4201d9262d"),
    (&[0; 54], "9a59350016540132bcebcb84110f6952decab504340b89a189178b992e1b5611"),
    (&[0; 55], "2f113669686f149ef5d9a7024631eb12134d6ec36306a22291b485f2fec59d2c"),
    (&[0; 56], "37d87925f453b19faae61935631462157c0168e14f0f819ec032e4b8b5eb2322"),
    (&[0; 57], "cbe5051164aeaf06012268c6c0c7b2fc951566afa32b20f31f0d9d0c4ffcc71a"),
    (&[0; 58], "18c238c1d0ed5dd696266ca5cc260afb6fc9737d86f6270f779f22f02f2a5644"),
    (&[0; 59], "6b4676f11f197aff674e88f05c5b8cfdeb3bb4408da0c713c22226e9c68552ef"),
    (&[0; 60], "286e4ac4211e7ad56db02532a197cea507f6c19ab8e5d6213be5a14f21ac2149"),
    (&[0; 61], "947f643d1c6fc13c84b844f06a5d0524d9bebccbf596e9c957898832f2b8cd4c"),
    (&[0; 62], "3474d6c54308ef4ccaee7687ae99a3a422aba1a2643d2e245fe381bcc4ae0cae"),
    (&[0; 63], "4a1da33a313229e6925a30300eb358815b384237c701ddfd817f535053361468"),
    (&[0; 64], "070fa1ab6fcc557ed14d42941f1967693048551eb9042a8d0a057afbd75e81e0"),
    (&[0; 65], "416aa7b5c0e0653066a7c64dbdd0009dbe84386151fe039fd942faa2db6172eb"),
    (&[0; 66], "196425eab9fa43b883f78fe7330b73a690a84ce21bdab3977dcf952c1f0a14ff"),
    (&[0; 67], "ed6b966412282df82c015944cf4b428815870acb804eb1fd944608bd64066130"),
    (&[0; 68], "62a50ca81d20b868aeab36e07ce3c5b491dfade82f01e29560599004eca5d387"),
    (&[0; 69], "e1bcf608a45df8a1bd5a098d7e478e4e0775f7b222a7f2b811b88d44f4ffc779"),
    (&[0; 70], "961cdd83c6c8b0991d9eb7f8a87f18eda5a8185694f6c864da07a8556b1ac1c2"),
    (&[0; 71], "c977561c52fd7401efef9f9e9c9aa00097f45b64ee1d9d5d750297f0825a2148"),
    (&[0; 72], "3a13d9739b15dbba9aba102cea31a1dd7d92e27bd60c8cf8a9ec34ae751b1660"),
    (&[0; 73], "edbc4e4d407fc32f34c7ec8ed9a76ed903bcbe44eddecf228e5f713d8797b185"),
    (&[0; 74], "527ae12e106062cf3f2e2a93484955767223a10f114b332a20523cee490b5935"),
    (&[0; 75], "efca038729c6fb8d15d483878d02f6a7e9aae8a3393915d53f3b5aaddc52d06a"),
    (&[0; 76], "2b224a20b7fc60d3eee906d514306a3d0dba22fa4b93b0984b24692fa40f04d5"),
    (&[0; 77], "ddd1d0613bbd677aa7097578441915bae45cd1014e4493b9738abff4341de5da"),
    (&[0; 78], "14590c51898bd3cf9fd0ff26b75bd7d1159c85c2540dc60a7a824cbe22dde1cc"),
    (&[0; 79], "56a052fc9ea73e9ca8d5597be5d3e95818042283b355da5edd7f8f7a951034f7"),
    (&[0; 80], "c5fa98aca9ec66e1373a5a65d6d9d143b9b77465402fc4cf1bad038d0ca3f5fe"),
    (&[0; 81], "87d8ca43275b16c3408fd931df9ccf227ca0ec16378ada484b4d7364f1e7a96d"),
    (&[0; 82], "31fae276e4b9d74bb93c8f4ca4c14644f57c74198d4e3ffda8f0a76ac1a91096"),
    (&[0; 83], "53dc3117e73bc5d124ce03e4f64ca3bf877992efc0f41d084e6c84d29f56f3fc"),
    (&[0; 84], "f422e2f778260523408e8c03df2379829c05fe5c4646ac22cf521ea6dc7dbf8b"),
    (&[0; 85], "dcc0170052dfb35940b2ba531d6934fdbdce1ccec70894760713d9a348889446"),
    (&[0; 86], "7b30ba262b44e05bfb2fdfc209b5beefdbce4f71c859ebdf2ed363682d8ee519"),
    (&[0; 87], "80f5fd17f66d0f8d894e1c8187e8fcc751b208286decdd41a1d955d48c8c1b8a"),
    (&[0; 88], "06cbb63d26ea8d240f5442c47e343e123a136e3cc105c542bb2c4e8d4c8c349e"),
    (&[0; 89], "f864549d80e28b29215ea985d6bfe7bf299ff7118d425381a8e1b7a3cf157780"),
    (&[0; 90], "6eb4d76e3b670ba8a80deaf38747d9b7f157c6436668fe5235485b0a0a505fb2"),
    (&[0; 91], "6db73fec74e79862f9a5176fa0b9205bb65c62138059e88ad01deb46ba8f1ad8"),
    (&[0; 92], "7becf30d534432649d4e6b49c67ca2b36d1369f2681b4ba10a5707d0621e084f"),
    (&[0; 93], "51459648a25c0a32c785c91686a3c2a24f97534257f4cd6bc7b2f780153bdbbe"),
    (&[0; 94], "7884d94d01a8e21274e563201d7a88480ba02645c42e7ad13675b15ea40b15b0"),
    (&[0; 95], "b4ee865fa962c263f495c9d1d95939c81116aa5dd04d7cf536748bfefbbd2485"),
    (&[0; 96], "c3efec14e15bd34e0ec1fbcb2d7f881ef64c8f44450a39fec3a2e57229bbf189"),
    (&[0; 97], "2e09e40d123b6d711f713aab5e9911ac79551e918ffbab4a5bc90d96d6bf7763"),
    (&[0; 98], "476d36109aebf33df818a95eff578887ed61773ef4a876289af40bc92e93f20a"),
    (&[0; 99], "6610fcaf515d55c46f235ef7a22e2bd2fbc8a8e3afe5e80906b20069af313565"),
    (&[0; 100], "496da9d6a23cfdb01ac5c98b5714194b07af41751a10358efbfd56e3d15b69b8"),
    (&[0; 101], "12c05d09de12a365c7408122dcedcc5c342f42b2c995c9e9bd40cad933ffe4e9"),
    (&[0; 102], "02fcc80f35483a62d8fb1a18078e0fa8ae5dfe49ad5d185ca3f1996301026df7"),
    (&[0; 103], "1e7920dfac45758e586d9969769064ad52e1cec3e7ec03bfaa7e92d5d1ea9604"),
    (&[0; 104], "a900456bdd9d1a2b84c06cca7cc0c348be1f25f6b7765a347e316b63a8482597"),
    (&[0; 105], "e2cf0c3775a79f6b18c05a3f19bbd0550d3db4e3df7fa4f0b9acdbb6979c2862"),
    (&[0; 106], "6818785dc701ffbef8f10bce702024cdc77618204770707d17a133159b02f713"),
    (&[0; 107], "010d1554dd82034f71541d309335c27ae469b8b7e2cfc1be24f71cb2fe4c6f13"),
    (&[0; 108], "edd9e366fcddab1cbf91ef63de8389b3cab7c7412f9866b661d9bfb54116abd7"),
    (&[0; 109], "d3d49d81b95ef29343ec7a02bb738ffa4835a3f0e5d45e422b0e05cf2290bc30"),
    (&[0; 110], "b40afc0d7bb721e781bdc827621850c5cdbea1868a145b47fbc14d0c4defe064"),
    (&[0; 111], "f5fefe425b2f526f9135be9e7ce32bdcf4824297bd9ff4af6a591bf4cb97dab1"),
    (&[0; 112], "bf434428f16922b234970fe77d9713591620bf0d4993374d1e4be7f15c5367e4"),
    (&[0; 113], "898eb60b7b5ba8a4a49d614d7c9f26022f8da99083ed23b5ad5a9d20768eb102"),
    (&[0; 114], "ab8316107166f564c7ab317aa1e0c4571debe82e7c0c13aacc85beac9ac28ca3"),
    (&[0; 115], "ac4b047239eda36b12a07b4d21b5720ed044213188b6593701f7e6e3ee878ab8"),
    (&[0; 116], "6fd8796cf63cdd19b22f156cf3cf41dc2329d5a13ef051f2ba955b297622b8b1"),
    (&[0; 117], "ca204cee2a4bf19ad10c22f461e26c061b5b6d3e777afef4fb3363b18688d4b4"),
    (&[0; 118], "2d3e6092d11f20eea76af37b4a5402ec1c5843bb867a0f2f816b9493de2ea6b8"),
    (&[0; 119], "03b378bf091f48e95ac8f82fb3fa828a9882cd00a6c00f195d300cf2ff6b8da2"),
    (&[0; 120], "b6e1f1e0adea98b5f46846196df329d0c617a06adc04d4382554dcc1a8fd7a98"),
    (&[0; 121], "e7cbfe4bc12e7e1b2914eb17a11bec64094c87ba0ef201d303d0f953c59dea14"),
    (&[0; 122], "81bd75eebc28eed49743cd2e9299e96c6dc2bfcf0389672f74dcd08b0d595d28"),
    (&[0; 123], "4b5f872bab78d982f51a55c78220b3928e240d11098b931da02ba38c39a19623"),
    (&[0; 124], "e262f7ae2b2ac948bf2e190c498026adc3498f185352f1e610875031ef1da9ce"),
    (&[0; 125], "463ee12af80481cf70bfd385bfce4987d3e54f28f9057aeb5c12a8fd6fde3d9e"),
    (&[0; 126], "cb45da1bd2c61a845db30de6a05608083f7d365550f74663678618180802e1fd"),
    (&[0; 127], "7c373503f6c376b652678ff26fcda6caad04187ca96d97301653ae306229c893"),
    (&[0; 128], "040689c9dbffcf94620acdeec5686d8c35d1c85f8f3c1a70b988d58ed33ea148"),
    (&[0; 129], "7f254c519667c56d408c0c390d46acc84ead1fe050081cfaea57bef6ca93ae66"),
    (&[0; 130], "5a30e96b0984e8237b6c70c81960ceabf30cc8823fa2766239bde4c3ed7db6ca"),
    (&[0; 131], "07e71a8b08dee5289d2ecad06af8d0d4b2be8536681481d066dc3c14889b62ac"),
    (&[0; 132], "7e635de280c13637362a6c51f69da3bf92829ab013f4a2e087cc043f761f00b6"),
    (&[0; 133], "ed80973595f3dd72ae79b2d41eed1b504ea7431b70135191611c8e2029ef2282"),
    (&[0; 134], "bb551c88fba60f9c030762fe75c16dbd589d690f00834374fec4556ec01064d1"),
    (&[0; 135], "7d080d7ba978a75c8a7d1f9be566c859084509c9c2b4928435c225d5777d98e3"),
    (&[0; 136], "e772c9cf9eb9c991cdfcf125001b454fdbc0a95f188d1b4c844aa032ad6e075e"),
    (&[0; 137], "9ed57188470a83b758cd71c00c6cc3beb984b36a6c35864b4e53017b24cf5699"),
    (&[0; 138], "d1fd51f096c13a42125dcd9aa9e6cdbcd634393f6e308ec8d52a885383ee812d"),
    (&[0; 139], "7d2b9dc3e8d63730a5ab418af224a0cfd5d9807f71c4206eac96a4de3029ec8b"),
    (&[0; 140], "2f82e7490e549072c69b5e230f65479c30710dd9816c82f018139f8dcd3b47e3"),
    (&[0; 141], "21438374073d008e97dccc2c6914b41b981ce2bc897f99a5053a7d8b59bb1dbc"),
    (&[0; 142], "31a181f92092b226ba87d88ddac6df0439be63612a40e9fce11791f78191cc15"),
    (&[0; 143], "18c534a2304ef09169790970a6a36f3468d0260cb124a624904f98847289427d"),
    (&[0; 144], "456545dd877291ac1c7b1e9fbef9ae1fc8e1eefe1f309ec56a5088bcbe9f9385"),
    (&[0; 145], "dcde44c71f3ba69eda4a71b98654e12f402c3e5a93c1d29bb269043cbe83c947"),
    (&[0; 146], "d3c8339e755c50bbe73f7233f0d7e718dbff2eb1c76f92e8aa88c35c2967fe92"),
    (&[0; 147], "217a98caa91e088c737267fac85c83392bbf0d3237ae9791d3cafdead3ee5692"),
    (&[0; 148], "88c525eb332048e0b516521aef3ebb324ced6400814b0554ebcfe773e591d08d"),
    (&[0; 149], "08bdba34759a20e89942227b4cbadba6b1c2838cebb1c3b4281baa71e2bda794"),
    (&[0; 150], "cb341b552e4f98e4568ac9cefda8ff6b7ab14144e71346c6405ac050ceeaa89f"),
    (&[0; 151], "0034c39e973105389de60cbd3ae4677b0984f5056589feac2c07af5dd235dbb0"),
    (&[0; 152], "4fe73e6dcd2baf43cc9adee1666e46ef0412911413fdd2501def51105a2b623d"),
    (&[0; 153], "2e69cfad28218b195c6eb438639ac11ad893c743f96bdff6ebd54d1e8cdd8f41"),
    (&[0; 154], "808533d5c34557016a26f9f6d242054835c47f08d7534d389a472f0cd3d3bc3b"),
    (&[0; 155], "e3e89b4fb1601d665ea88941582fb766f9abe162a307c1e2c5444a4a9a5907bf"),
    (&[0; 156], "27109f0b1e538b9c5bc70503a8d8d24211d57b55b169484d41d509d6f57732ce"),
    (&[0; 157], "739ba8444fc33f470b85df91792c5795f1471925cc8bc9a986a9435352341a1d"),
    (&[0; 158], "6164286b2823dbf94f7831c5e55a965238b0ef9984a4589361159b7f6ccb8017"),
    (&[0; 159], "4b8441f9e0aaeb26d28824dda3662ed29de3df5fc0e814d6ebe521e2a454b2b3"),
    (&[0; 160], "56f3eace85399bd5c9f3b5ee3e00b0cbbaad98a04f80174c0efcc1b4fe943857"),
    (&[0; 161], "610d30d97c69eabcd3c5d207162ed86ce2dd0361c7f9c9c3ef6cba354e364da9"),
    (&[0; 162], "dca0d84e08a9970455a493846038e105c1f2ee911644772edbd6b492cc54cab5"),
    (&[0; 163], "b562f9f865e4b968a086d526515427b243f2be332e138683693ce7cccad52c15"),
    (&[0; 164], "49b1a1e271ba29fe5977e924625b8a1933a9b18bb519844852c041a6187a02a4"),
    (&[0; 165], "96f68f29d34faf9bf9b5a25f15caab45976c23f2578b43e6e7ac4297e2700405"),
    (&[0; 166], "8299abbfbbc5c3834e8461aa7e0c97ca6c9b41c9224deaf627daa1d9143680e8"),
    (&[0; 167], "d27646442cbe40675c0a7893513a3343436d71862bc52fb0cd4e8c9445f31079"),
    (&[0; 168], "befaebb14926b3bc6d3330ea240dc2f202a15ddebd0ac4f50a0195d7928acf5f"),
    (&[0; 169], "e835846a9f626d37ace3856c95c44d75ac9ae086faa3da419d524e0c68de8f32"),
    (&[0; 170], "1230f3c121a734f54de3fa99d0da6214381ffed893b72fe4d0fc4c577058bc38"),
    (&[0; 171], "bbf912e65dc40e805ca23c66db05af9c83952b6aa864cd23e2e8d67a1f8993bb"),
    (&[0; 172], "5170ca66fc0726904f857b215753d2aa106b51dcdd433c6da92918276be49fc0"),
    (&[0; 173], "f8d4788ca58607881b767998b32a876cd73ca45a41c0df5020d51e87e757cc87"),
    (&[0; 174], "2e0e034c8899a07228afe89866fa2bded7767f68a3bce06e1d47d1c75b33d571"),
    (&[0; 175], "21a6df470f10dbb3fe9c854631f1e71b069043eebe118f155a2801b90b5cf459"),
    (&[0; 176], "8a9cdaa41a4098a6695cf2dd1ec4956e7fbaf26e199ff62f620ed50dec190811"),
    (&[0; 177], "6dd7d216ffc439230b62c328498269a842ec169d0a20cd4174ecc2a0e93bdf0a"),
    (&[0; 178], "172a7a49cbe9715732ac1507d836cafcb91f8d42b5e5e8d6d2ccbd7b387ec789"),
    (&[0; 179], "3887bf6fa01644704198d0bc67a67d988f9cb881342cc634c32d43ab1554095f"),
    (&[0; 180], "91b260ef685eaef11d601c34debbcd44f1c3980b2571482920e884092f82e666"),
    (&[0; 181], "bd542dd03aea838293ee07ee832564c6ae379d286451193fd7760facb2427c52"),
    (&[0; 182], "2e2804ccc06b8fef78a8ef3a0748eaa64b408730643248c28391b681bc123169"),
    (&[0; 183], "1a88a23434df55c8dcf88d50b8aa580fde6b9e50c1ace840b50e4b18f6feab6d"),
    (&[0; 184], "845cbd3db6727d0f00f11759a3fd45b054c34b907de9ede31a7bfcd5fe9aa76e"),
    (&[0; 185], "ef3c6e7fcf5d6bdaec28cffa0052a223e6e7c444f93bd3d19458b74aef585bc0"),
    (&[0; 186], "4691d3909e11496df1ef1fb54e25de485bb601b8294989e39859e4fc255d268e"),
    (&[0; 187], "8bffcb82b92092666a8f5596c59a5b9d69543217683ab9186b471e249d60b466"),
    (&[0; 188], "106f99a1b449ee71ee80458195ac6d5e027f0813f7824b702bbec84606ef3dca"),
    (&[0; 189], "c7733e8314a85cf3ca0fe806325c3e6e68a62ee835e11d8ed18446159da804e4"),
    (&[0; 190], "0391f1109ba02021f27558617d428c2c12b141e03b43058a63b4d91595ba88e1"),
    (&[0; 191], "0b192f83d41f17c6112de09dde76c11f228694dc6f72e52774f4d572c02237b8"),
    (&[0; 192], "051323892969e8e6d9ee971a79133e3691e1fcee6e133e07e3a87508755f44d3"),
    (&[0; 193], "f8a58e89e86a9b7bfd68e9ca274ff16cfc11207575e679d956fec99b32b79bf4"),
    (&[0; 194], "83007d1c54526b18fb6a8341a7a6f233aa1cfdad8ea047379d1655c6de41a2a1"),
    (&[0; 195], "72ce237882dd84e8b43c0a815c3b0edd1068a02f89e1f9f5daba52c5b88f76b4"),
    (&[0; 196], "2240133611898362dfaf4c640ade1530a1ff9f9e6eeefba35552812037ae038f"),
    (&[0; 197], "9bc5ad7b63339c9088f38e87e4fae1eaa4d373de250a83d55eb57b8ebf230b21"),
    (&[0; 198], "32131790961dbe8f94d9abd9a2dd356b8c55a79ca17c187e3e6c3c97088a2528"),
    (&[0; 199], "847ac5329f20d73d9df50490fceae2ceec95753c473e839e6f5214e85f8782ee"),
    (&[0; 200], "2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e"),
    (&[0; 201], "e0232e1060d7f5337e66aa3b1098f5436d575a307e33459e2007aa2965fef8ba"),
    (&[0; 202], "60a1b00d0f515071c1d59e01e1437a1f280a6218d55264214c8fe8e02893e56f"),
    (&[0; 203], "13ff014add9821a79948e94bf271b9ecac6223112a1d1a82e9a1deff3aec2e26"),
    (&[0; 204], "26a435dbd2fd903e43d37abf7de6fb65888d67d2001e239f7484d4482c66d7b0"),
    (&[0; 205], "4ac00e117278b3f810d0123eacc4e2b975a471e54316e40e185ee0ac235c9e7f"),
    (&[0; 206], "ecef85e31fbcd556d4de78d009bf7abbe7c0bfe597923d49c848a815dc18c231"),
    (&[0; 207], "0211fc83878b9af262de6b469c1d8dcf9a1117d41e5db455058b36a64faf753c"),
    (&[0; 208], "1898020df56c4293e6058b583fe4f971191c7ad4a70c1d140f9b494d93380a67"),
    (&[0; 209], "8a4dac4fd3ef07741d0a424f45f3a4939041e3b253aeac65c92a085bf3437ecf"),
    (&[0; 210], "573b0948e7a65450fb7de8d4582e93888eee1a892bb3c71583b8a004252b7cd3"),
    (&[0; 211], "6d8d75621a00452decdf21a890c2dfd733c5b9cc46e3a96f877a04191b3995cc"),
    (&[0; 212], "4431a99723b381df1f90bd7b526f873b6457fcfac7ae7be1c6ca5024609baf76"),
    (&[0; 213], "29ccaeb627bdf36e1c6a0a1d7472c602c56b42649c4eb8d6b7d452ba27ffbdbc"),
    (&[0; 214], "7f4983f8800424eaf302f6f9899f7707f37366eb58dc568e0310d0639a3d0376"),
    (&[0; 215], "2954169ee31cae8bb41fe3b0208f59ca4e792309a76d7e3319ff356b460c5857"),
    (&[0; 216], "3b33c87bd6a72ef4b34d3fef6fa4d7914aca2f06b034a66a91ba8ccfcc3f7f32"),
    (&[0; 217], "ffd73457a68cc0ecdafc75c3ca757ccf98da977f34f5809997dbef82eac3e024"),
    (&[0; 218], "155b8eb9d836818f2d52767496130b700f4c7ef6b8aa02f9014848987c21f358"),
    (&[0; 219], "c39ca852cf8ce5eb5018d1dade90a49e9da664d23562ec2342a7ba41ae8c1f26"),
    (&[0; 220], "9e7bccea5e23899490e0a248bcdb1ba6f0bb23beff62b336517d79a187035506"),
    (&[0; 221], "8cc7d376186d748675f3b4a1cf67930cd27c5cf14f81250ae28bc251c541e374"),
    (&[0; 222], "40adba10d99b8312d878e67932a3cc175379be330cee5a381f969657060661d3"),
    (&[0; 223], "9dd35cbadb432aca7820eb080ed252729156cabae5633891f1eb433a4dc5c2ac"),
    (&[0; 224], "818078e737c3d8ddd6c429b1c3d6ed3c4b8c3fdbf3cbb7672ca771fcb6d45043"),
    (&[0; 225], "907d0f1b617c9e2ee4029dc912562540c2890a76e6ab18b7476f367639de3422"),
    (&[0; 226], "0fb25bd12a85c88db4036d63dba0c97a4eed9e0d809940af0cbe179bb25fe333"),
    (&[0; 227], "b9628d24158b83d65f80f7f72a588c3495d33f201aa8c658379ef00f9364a24c"),
    (&[0; 228], "746f5753fb89d8777bcfbe18a80653ecd97741afe93bdb5a03f2fc0244473f61"),
    (&[0; 229], "d71be87d6ed2fbdbc2229958a14be82d57aab6d4d21bc82f7fc9e48d3c7d65ed"),
    (&[0; 230], "894e66147d898a7a7543848d712e52f4c1875f2b4f762cb1b864576b8e1ce140"),
    (&[0; 231], "1ec844f6c3ff2149a6268466190b9f0ca9926f631a54e9ee4f03bb3e82a7555e"),
    (&[0; 232], "2a7a702bedde59e1204f341499e4a0f15ab4857fcb2ee48ce17b945ca29d933d"),
    (&[0; 233], "8f4500f71bd0bd90b8122eccefa441a12d8181a3e4298e6ee9bee7354f972307"),
    (&[0; 234], "3a44056a823ffb62c8d2b0b560fa599ea300c32b7d86edfffe7818b50020d2d1"),
    (&[0; 235], "8ac60198e6b6f84cd085c242732c8aca39d88cc4586af31e3c0dcaf03179c367"),
    (&[0; 236], "1fa646b717c77b337d4883869ac9d3b38efa27a378e80884652b4b9097727cd2"),
    (&[0; 237], "6900760b76886c247aa11244411d0ebb92dc3aff24edb61a2f89192c6d882455"),
    (&[0; 238], "5f9f8c46a3b664d260a1b67588a124211f440abefcd287606ceead1192ca7f1c"),
    (&[0; 239], "5ed611811951cd8b61319c06e4ed4bb548984ef03d41e34f3850a0bd6044b5ae"),
    (&[0; 240], "095170ca80b12ec9bdf8b39ad443f47d3bda42aeb85b290c5fb2a29deef244c4"),
    (&[0; 241], "6e40f11b8de543198d790d501e909d7b895e1b77367c43bcdbbaf689663a89ee"),
    (&[0; 242], "12cbc75ba00af5e6aba079eaaba5db9023b8b587f352a45bf052a5b54e04f41a"),
    (&[0; 243], "fd938937cb2b2ed32f509ea140d93a9cc00a39003b9745569a156b47b438e3bf"),
    (&[0; 244], "ad17cb196f25d881e83209846061c9a70457aa2a6d5a5b2dc92d958673cef874"),
    (&[0; 245], "e7d68260417fe9f66eca8c7483213118ee85e5d67a6c0db2f12e765db759435b"),
    (&[0; 246], "2d12a3a1e26a2636c1eb40ef2b524057849cadeefafcbeab9ef47803db217b05"),
    (&[0; 247], "58b49b2d51e4bd991e07347800c368faa60ffc1851caa441a88241d2bd98196a"),
    (&[0; 248], "ba1aed10a445f3246c28dbcc922d8b0baa4d78fca0bc91ef61bb48c0675d252a"),
    (&[0; 249], "84220e3b06e0596b478281e76ce8019e6c9499550b18b681be5c5e53e5a6502f"),
    (&[0; 250], "7da1a569fdb1685941d9b94179b4b8db8278c4c49fc75d964d196dfac49ddfee"),
    (&[0; 251], "3f4358d6081ff2d8dd0456a2c5d56d4a669c1fce84d92d90c37f01df382129e0"),
    (&[0; 252], "4f3b8b4222c2945433e9ee50a32b4aef95f41a595ebcd07b87262657a03912fb"),
    (&[0; 253], "b7377cc970e74daa5840347397d0c4d8127c4b1dda1de6910df3bba91e962e65"),
    (&[0; 254], "75edb366efcd70dcfb3640e8bf3b9b55d300504ca2775745cb3d4af05be6c661"),
    (&[0; 255], "a5bfab305ac4e3f7b46df197e00dba7362d4c807c681b70bc63e52541ed69ba6"),
    (&[0; 256], "47af990afa74cf47281fe85246e796e7963fce8e05c443d221aaf1ebaf238b1d"),
    (&[0; 257], "2504e069de543d36aee52a93110578ad9a974b7c9e06a7093b174c3db7d3df45"),
    (&[0; 258], "98bbd09c241eb7ce0cecbc8b82c10251d889a1ba64d702c9c8612a23712d05dc"),
    (&[0; 259], "2a7acc639afb9d451085b3a1598863d70343ad888d8e2c8a68273f16fd2595a4"),
    (&[0; 260], "a6145d89eb896eb08efba0e69ec955a3433e2635d9320bbdc3d928b9a69ca8c5"),
    (&[0; 261], "c539bc160a248228171a3121c9cf8478c917b138d23b5b612997ba8e2bb77b2d"),
    (&[0; 262], "b55a248b5c5211f3380a3cfaf66e74ea76418cf223e333d138b43b242bd0c8bc"),
    (&[0; 263], "921ff3ba98e5178c86df076b404b27b6cb565b23048f85de4552a2cec9107ed4"),
    (&[0; 264], "f0fae437659b8ad248524742d66ecded63525e30afcf9dc96e047edf48277c9b"),
    (&[0; 265], "096b5fc695b813b93c4031e4e285e07183099218adbc93a6f9226360e046bfb3"),
    (&[0; 266], "0c6a19122b465591df7b9b9cb7f519d2f3304c253623f6d28a15b55b7c8f222a"),
    (&[0; 267], "895501c8a29de4cb78f2521345d191eda6c53d22cbb31bf9aaffafd483c3c1ce"),
    (&[0; 268], "e206e766a73478096502805e53246dfec37aa80523b1339101f8b84a11192538"),
    (&[0; 269], "01bbff4b1538c03ecce8be3e21483cdd340b66c808d1b6d74857b17724bcd204"),
    (&[0; 270], "6ce42636bc8d39c00ba7ac3aa822c50fa426e2543ac2e0f264b6ce4f4e6f8d81"),
    (&[0; 271], "d320e3e392e000b3ce18050d143f8fd8dd655d5c80a724a1e1be28f083a35ebc"),
];

#[cfg(test)]
impl crate::hash::Test for Sha3_256 {}
#[cfg(test)]
impl_test!(Sha3_256, default, DEFAULT_TEST_CASES, Sha3_256::default());
