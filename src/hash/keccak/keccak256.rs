// Keccak-256: [r=1088, c=512]

use super::{Hash, Keccak};

pub struct Keccak256(Keccak);

impl Keccak256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self(Keccak::new(1088, 512, 256))
    }
}

impl Hash for Keccak256 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message, 0x01);
        self.0.keccak()
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak256;
    use crate::impl_test;

    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); (1088 / 8) * 2] = [
        (&[0; 0], "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (&[0; 1], "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"),
        (&[0; 2], "54a8c0ab653c15bfb48b47fd011ba2b9617af01cb45cab344acd57c924d56798"),
        (&[0; 3], "99ff0d9125e1fc9531a11262e15aeb2c60509a078c4cc4c64cefdfb06ff68647"),
        (&[0; 4], "e8e77626586f73b955364c7b4bbf0bb7f7685ebd40e852b164633a4acbd3244c"),
        (&[0; 5], "c41589e7559804ea4a2080dad19d876a024ccb05117835447d72ce08c1d020ec"),
        (&[0; 6], "5037e1a5e02e081b1b850b130eca7ac17335fdf4c61cc5ff6ae765196fb0d5b3"),
        (&[0; 7], "dfcbe054725ea501056a95ff91530c2a83371e15ec9d05619f12c76baa92ee2f"),
        (&[0; 8], "011b4d03dd8c01f1049143cf9c4c817e4b167f1d1b83e5c6f0f10d89ba1e7bce"),
        (&[0; 9], "ad315e209dd62516ab8c7d1c2d8c3c206525501ebef91d12c34431f9ea255371"),
        (&[0; 10], "6bd2dd6bd408cbee33429358bf24fdc64612fbf8b1b4db604518f40ffd34b607"),
        (&[0; 11], "6f9c0300d90788e3eaa2560d9c84298b436854bda9b9a4a9e9e04faa2e5e88c4"),
        (&[0; 12], "30e2bfdaad2f3c218a1a8cc54fa1c4e6182b6b7f3bca273390cf587b50b47311"),
        (&[0; 13], "3184fc86524b0495db56f434fba34e478911db355cbb44815e987625ab42e557"),
        (&[0; 14], "9166c8d72e513a9e3b8389c11481ec071da93e37370fc62bf99c51a7b869a7dd"),
        (&[0; 15], "bf1039e9d8f458cb0631edfab4902ce135879eb69e38484e881a6574a68ba9c0"),
        (&[0; 16], "f490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4"),
        (&[0; 17], "5b7d7eba22589dfe1bd7a5417faa2a79838f19c58fe7408d6f66be2327cc996d"),
        (&[0; 18], "5d8af3eccd090407b914616ecb273b9d6c3321c26358e846ccb87a888d338b27"),
        (&[0; 19], "5429fdc28e48579bde709c0ca18c55d58f14c9438d5cd1829556be99fd68b97b"),
        (&[0; 20], "5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"),
        (&[0; 21], "5a657105c493a1213c976c653e929218bb4a516bca307dce5861ec23fffa4e58"),
        (&[0; 22], "5562d44b8038c7ec81ac64c10e44ed3b5638aebd3a8cb9d4231533aa9cb3890e"),
        (&[0; 23], "e2b9f9f9430b05bfa9a3abd3bac9a181434d23a707ef1cde8bd25d30203538d8"),
        (&[0; 24], "827b659bbda2a0bdecce2c91b8b68462545758f3eba2dbefef18e0daf84f5ccd"),
        (&[0; 25], "c0d41db1b6c5cd39e7205798b17f08eb6fc41ffc96eeaace0bef52fdf71aa9ab"),
        (&[0; 26], "a533db48442c1c18882149f8a3b768b48288edf57aecf5122aa8b9170d52dcb2"),
        (&[0; 27], "59642f809245ca2950deda7acf1d460ac419ef7a8d003ac6bb42f69b01891e5d"),
        (&[0; 28], "b696031ea0505df7c7b5cc290e50cea0402d2a396b0db1c5d08155bd219cc52e"),
        (&[0; 29], "471ccdcb79bddea38175f8cc115b52365f2c864200fbce48e994511bb9c6006f"),
        (&[0; 30], "f548e71c32522ed78c2588df2cfdc3acd5c04cf930953ecabcc86ee3532f317c"),
        (&[0; 31], "15fed0451499512d95f3ec5a41c878b9de55f21878b5b4e190d4667ec709b4cf"),
        (&[0; 32], "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
        (&[0; 33], "f39a869f62e75cf5f0bf914688a6b289caf2049435d8e68c5c5e6d05e44913f3"),
        (&[0; 34], "bf53adb76067fdab0d008aef3ad8b28bbb63c2ce4c2b63394ede73f01a70c865"),
        (&[0; 35], "ca1c89237bece40382b71cc333f0cf90b8d896352d5f336ce534d6875b926e2b"),
        (&[0; 36], "74723bc3efaf59d897623890ae3912b9be3c4c67ccee3ffcf10b36406c722c1b"),
        (&[0; 37], "96e2012ae1835f1b97d8521c4558a877b98f5dbd5fbe082f6a7747eaa649fe09"),
        (&[0; 38], "913b834257c793da6424db222da1ff2f6fd6170ac3094be0405cdcc5552e1a78"),
        (&[0; 39], "cbfc9f3ace1802ac45478ea2849968b5f2a6895f1c4beea8e29085ec84a2fe43"),
        (&[0; 40], "daa77426c30c02a43d9fba4e841a6556c524d47030762eb14dc4af897e605d9b"),
        (&[0; 41], "8c3a47de78197a12495b1b381467f70d10231a44907e73dacc7c548569326dc4"),
        (&[0; 42], "cd2548c4fa14cb15667cd5e5667dafbd0970d09185c619eb3348f5d7dbf131ba"),
        (&[0; 43], "dafb08ad2e8051263f565108f38cabb76abdca652cbe1b7f859cc22e76f2f85c"),
        (&[0; 44], "44a25c9533b4c9e05472848068a6b5bcb693ce9e222f3f4ac82d2927a82a34ce"),
        (&[0; 45], "009d9ee6ae2a8d2d33a6152cbd20b53e8e846228d6f5c3ba6df1c81f16d3f127"),
        (&[0; 46], "e8fb33650faf37535ebd07826e66bdb5c39fb2091055617df310736132d8743c"),
        (&[0; 47], "e540257305ba7ed8f0852280a8bb5fa439642e2bbe5efb8396023190d1d4efac"),
        (&[0; 48], "c980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293"),
        (&[0; 49], "184125b2e3d1ded2ad3f82a383d9b09bd5bac4ccea4d41092f49523399598aca"),
        (&[0; 50], "767bfb6ead6760f170718f8074950b9439f9d58e73b64f2554c474039f0e3eb4"),
        (&[0; 51], "e168b55b543959bfc9a1ba0d6f846406e9c5078c9f20fb49488e72c3781df761"),
        (&[0; 52], "a86d54e9aab41ae5e520ff0062ff1b4cbd0b2192bb01080a058bb170d84e6457"),
        (&[0; 53], "4d8a735acc38ab7f01310ca8e6026ed9f86de88141cd83996db741df5291fc0d"),
        (&[0; 54], "276d032750f286c508d060efcddd1b7a9becbfdb64efb5dfcbee057f86722fef"),
        (&[0; 55], "41414fecbcd48d24288f4cd69cdc4f11560667f16291c4c642082019a2c613a6"),
        (&[0; 56], "660b057b36925d4a0da5bf6588b4c64cff7f27ee34e9c90b052829bf8e2a3168"),
        (&[0; 57], "adaf372fcd93e6510620653a95d8b22c5e3c1ac0536d7b2362a5bbb3c7b49df1"),
        (&[0; 58], "7cdb9d7f02ea58dfeb797ed6b4f7ea68846e4f2b0e30ed1535fc98b60c4ec809"),
        (&[0; 59], "94374ea151ea3e73d7dd2fb895cb7f0c645bb54bd2d9a388e6209a57af17a19f"),
        (&[0; 60], "2af357fc2ab2964b76482ec0fcac3b86f5aca1a8292676023c8b9ec392d821a0"),
        (&[0; 61], "1d8453ab2f7716504a4457ebe9831dbf996267e350ad0b2029f654d0dce1e055"),
        (&[0; 62], "2e795758918d9c804da815b3be88b798e63d21d668c624228fbd697bff25ea3b"),
        (&[0; 63], "0f81fd306d0c0cddd0728a76e6bfb0dfa12891c89994d877f0445483563b380a"),
        (&[0; 64], "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"),
        (&[0; 65], "ae61b77b3e4cbac1353bfa4c59274e3ae531285c24e3cf57c11771ecbf72d9bf"),
        (&[0; 66], "3f6f363f9f5dc4d17b6302009df91c84926a6d7684d5200cf7564c162d14ee9e"),
        (&[0; 67], "d3f825fab1d4a425ed2702aa02ab5881c1d35fb3b8b952901dbea314309e2061"),
        (&[0; 68], "5706de766d5661c754fb7b4c89db363309a9f89fa2945c9d8c7a303b79943963"),
        (&[0; 69], "3e327054f60b9c38a1c3fafb23d155d0f971a83a616685eb79c73127b3dfbcc5"),
        (&[0; 70], "336c5ee8777d6ef07cafc1c552f7d0b579a7ae6e0af042e9d18981c5b78642d3"),
        (&[0; 71], "2ced9dd329f90a9efa5f4e1036cf7d16762391ac0cbe8efa32ce5639ae85fedc"),
        (&[0; 72], "3cac317908c699fe873a7f6ee4e8cd63fbe9918b2315c97be91585590168e301"),
        (&[0; 73], "39aebb35169c657d179f2c043aaa0f872996f17760662712f1dc6331fda57882"),
        (&[0; 74], "53e7852638024f004d43a4be0eb8fee26a32a8372274843339b422448fd2576f"),
        (&[0; 75], "743fe1979ce56df143c677aee6cf53601258e834f8e5b1cbd7034b3dde6bc8de"),
        (&[0; 76], "dff4c3682adc47c34a7d4e71e6d433ccc3cee8960cc8356979f56e9ca61a63c0"),
        (&[0; 77], "575b3e1ddd7d4ec1d0695cd1f4b1c0daa01cd98c8309e0d37422fa675d95c614"),
        (&[0; 78], "5e54bc0a1194513341483ee95706fa9d4a9831002cf6e153df784ce8a4122e31"),
        (&[0; 79], "6a697d43a20a63e9c2fa5aab8419182ead1753af13004c66ad1b554bf6f4d618"),
        (&[0; 80], "3a709301f7eafe917c7a06e209b077a9f3942799fb24b913407674a4c1485893"),
        (&[0; 81], "51980562e41978f15369c21f26920284ac6836d53b02cd89edf4fedc97e68215"),
        (&[0; 82], "2039d7a642a51f16527f26c248d83d01f17bd6bb26f8f7a26a8ef0b25eba8fb5"),
        (&[0; 83], "b053beae235e330995e8af215e2c0fa8f3c3b702f86658a43c0f626cd06a9a33"),
        (&[0; 84], "7733ef1f65c467ebbbb75072ade6f3677cc49a146089f0a95abd1e4015c837b9"),
        (&[0; 85], "40e863c4bf2d8368d2089be3cd3340ecb9c7be11c9c8f4588f2c50f607a3192f"),
        (&[0; 86], "ac5b832ce7527996a1c519945dbcd7564b88139d3ea3c59607b93459d99f841e"),
        (&[0; 87], "8793e6836d0a81896acf9611001258236b1803cd63d84819ffc0c54e4f8bf055"),
        (&[0; 88], "72abee45b59e344af8a6e520241c4744aff26ed411f4c4b00f8af09adada43ba"),
        (&[0; 89], "496e418294117864002a95f894a01c9cc414c86e17325489a5ea2f0eef181967"),
        (&[0; 90], "dcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2"),
        (&[0; 91], "69a7b944221b2d0f646f2ce0d6fa665e124d14c473efc07ff1eb0c83454b4ae9"),
        (&[0; 92], "70464a66238eef9fe6d03af376d9ed5260552f234e748fae9663a0527ef34c5f"),
        (&[0; 93], "a2cb1106ca86af80134921e46c21e7552734ef973651d0bff2574d844f46f814"),
        (&[0; 94], "04f4a4a9c6d36d0a720cbbc0369a0f0c50f10553d5bf85cdce61efddab992c3c"),
        (&[0; 95], "6ae96a95a7e84d959a072f5e21b3aab63a0aa74ddfcc855dd22efbd350b2b996"),
        (&[0; 96], "46700b4d40ac5c35af2c22dda2787a91eb567b06c924a8fb8ae9a05b20c08c21"),
        (&[0; 97], "2b429e4eab6541b4beccc7b602371aa993f406b84ccf73c8867b6d83cb135f94"),
        (&[0; 98], "9fb46c079060b754f8d357eabb5846653dacf180a75e2fbf304b5f377689270e"),
        (&[0; 99], "7832a610e1da8a92556b75303c954e5e61fe6fa5c988b6cbe4bc820fca21f82c"),
        (&[0; 100], "913fb9e1f6f1c6d910fd574a5cad8857aa43bfba24e401ada4f56090d4d997a7"),
        (&[0; 101], "8040878939e2c2552c3431a2511ce450ff2a10c780f6909ba3178ca99c1f8abd"),
        (&[0; 102], "144506fba465a18c12f8dec58731114f16947948c1a28ac35760a29331408b7d"),
        (&[0; 103], "b840f013b3b0bc1769ace30e7770764f63d4085eee9a18811cb99c138d92d2c1"),
        (&[0; 104], "c24cd7564e291016870aca25c634ca9ab560c07c935b6c0fe3b559cbd3de7501"),
        (&[0; 105], "0ef8d68719981eb44842a701ff72f7c020afbff94a05150755c325fe68802fe9"),
        (&[0; 106], "39989ce1596825781f20bd84047e3dcac85f96589cf76b6f5daeae6d96842b6f"),
        (&[0; 107], "79ad8017e5f801376d50ecef2e80e6adeca94733ac811058ecbb9921ca532eea"),
        (&[0; 108], "04e88d09225887e160a3dfd539d0a1be0108b2901a83eae56a864dcfe88251f5"),
        (&[0; 109], "7c456b1ccc95c604102f0ebbe2d79e470d02a42b75da1762ced0ea0f0631a08e"),
        (&[0; 110], "ae96725304bccfe12cc42d6371a36b5262e19e272d8de3549c264bc0161ad2d5"),
        (&[0; 111], "b66f629b5bf6dded995c034575c3bc0c5bb80f1180f2f3fa270b01399e416700"),
        (&[0; 112], "f13c0ec1ec54518bf202c14532e80c056dddc3070b62bea74dd43518f043b975"),
        (&[0; 113], "a7bcbe16ec017bbc48d6e83da0daf3f3a571bd2e92d464029950c43bef2dc67f"),
        (&[0; 114], "708140864ccdb67eb052fdb62da4e4411003c2749eeb5f9986de8f0ff3f64e63"),
        (&[0; 115], "4f4d5f332fbffeeac1a0e2cdf63db61aabab94e47201e7617dbfb1ed27a77081"),
        (&[0; 116], "3bdd562417b2b6c29b6c37a0fbf5c08139fe63f7baf013194f112d8319bf8b32"),
        (&[0; 117], "588546b1cb703864853438ca0f81c8fcd03fcc8bd024c758ee02587c010242a8"),
        (&[0; 118], "f591e143589af8eaa3ab69078c6a80c018df74dfecf760717c3ba8594bfd9d24"),
        (&[0; 119], "e08fbaa84828fa7e39489aa1d494352a5deb2c0a54f469154dc9e1553bb5b8e5"),
        (&[0; 120], "46da8fe57453cb42871b55d14b856565e2eddd78a8bf81928da79a8962274769"),
        (&[0; 121], "7f74e58579672e582998264e7e8191c51b6b8981afd0f9bf1a2ffc3abb39e678"),
        (&[0; 122], "16ba7f990509be07e4c437e2d93917ae094d98f39d0adb8f5539fd728be9d3fc"),
        (&[0; 123], "94bc2d696cf5357e2cb03d9a7147f60c5e064fcfa7630b44c45b99a39a5eb734"),
        (&[0; 124], "ad1f13dc0dc4a1394dcb2edf6b5e33485c0ca8e4238180947b0e8c460340aae2"),
        (&[0; 125], "9576cc8f5af0fbe387385b2393c7db89fa8975920a23953fb248a2b2a904c8b5"),
        (&[0; 126], "e957fff6a0df70ba27fbf4c39ace11c449dbd1b692a0fb860655506f8a27805b"),
        (&[0; 127], "8f2973927e9a384995ed617fbe50d664787eec94a4525f9fb33a2c340fda22e3"),
        (&[0; 128], "012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d"),
        (&[0; 129], "444b5adc238afc6067148cb80b10b6303dc34e35356809851c54631d5a0e571f"),
        (&[0; 130], "e8bd2ca7253bf2754514f6439facc66764fdd86e37c18880da0ddc24d6a8a12c"),
        (&[0; 131], "f039c3e59f0fe529646f1b11423926c0d8b43c9e15f47610cb3b2601eca203c8"),
        (&[0; 132], "7b91ec6fc5a634975d5512158d046d52c55cc658f7368187cd2ec4661090e786"),
        (&[0; 133], "2ade82a4561a3c0b5ff5fef46f1528d77a04efd3d1882ba2777862c49da1f837"),
        (&[0; 134], "20926439d7d1663c4d224931643bb513f3ebf181ab353278b24399f518dc5f97"),
        (&[0; 135], "29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e"),
        (&[0; 136], "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9"),
        (&[0; 137], "bee7fbb405cb0d91a8775e338c4a5e4b5d6b2d051f687fa942043cffdc73bd28"),
        (&[0; 138], "c40519aebd16bdfddf4fff6143c9268edd3f92d2ac01d4f9c79f67914faa2202"),
        (&[0; 139], "137affb8df2488f79785853f0c6d41aa47fbac17c7e885b087e4b17468ad47a4"),
        (&[0; 140], "a9df0c6e9760d69fd65101113d496376194007a12292eae166325e79131f4e7b"),
        (&[0; 141], "0888189a9bc0687053d91dbb4a6a5e8356874e5ed3c945e998a220f3ae961190"),
        (&[0; 142], "08de5f43c85d36c092be26e3e067bbe21229c12ed62dcd4a06cfe087c2b1e008"),
        (&[0; 143], "3c571b07d7a4a159444dfe7b07c54924521d7d2805731295727e4048573ba9cd"),
        (&[0; 144], "cd2e66bf0b91eeedc6c648ae9335a78d7c9a4ab0ef33612a824d91cdc68a4f21"),
        (&[0; 145], "34d8aef13b38dc7ce6f63eee3261808a00c5a54ce636e8a6e1904ff71a763c69"),
        (&[0; 146], "1c0b7b038a3e3180f1c4c4c7eb344529a4a174cc379ad6e572f5d36a450ec832"),
        (&[0; 147], "6dc1143605c58b5eff60021c6e764eaaf0452cf9d00c81a2e853f91e354e1f37"),
        (&[0; 148], "df2dce66784a9bb231911f54817836d5568a99bb60aeb5bed0eadf2f3a6585b8"),
        (&[0; 149], "6e2e44f5607c8cf87b79133b6283c416e5cae148cdaeb7c70d1e64647aae194a"),
        (&[0; 150], "ddcc9dd943d3561f36a82cf561c2c11aea2a87a6428627aeb83d0395892a39ee"),
        (&[0; 151], "f91d4a71ccc36b5cba8ef41f732cf5eb43ed5b29dc2ac1af2bb113b482771190"),
        (&[0; 152], "93e39c98d0ca3179244ffea1b925b32d3d0a932cf74a8c6ffa1fe81ac4c1f1d9"),
        (&[0; 153], "0cc5acc111533803af98cbfeaec4e0ecef1e4e9b10316696eaae951abf39bbd9"),
        (&[0; 154], "a0927ce1b2479df719d57d206de3e3c631b09cd23dda045d06356f50e0e4d2b1"),
        (&[0; 155], "dad3d0b23786fc6c5705b8d5a55bce115a585f4a41a3615b509293ccc7572a67"),
        (&[0; 156], "992a74470ad5d0f82b73b49089b520ad21ec26043e84c11a3b29df8392c8fdd4"),
        (&[0; 157], "bd0101819b867a784cdca2509b3f74e4c3657815093c1e9fa7466a7ceb5f9e7e"),
        (&[0; 158], "57f16f13121584b0e3d0567264f2a083bcf4f8b31ba92aa4f8318800a930da5c"),
        (&[0; 159], "f17ba4b84d864323456aebab4d2eb74934c99e333c83011674502064e6b6c00e"),
        (&[0; 160], "dfded4ed5ac76ba7379cfe7b3b0f53e768dca8d45a34854e649cfc3c18cbd9cd"),
        (&[0; 161], "01334b96c6f1baee2e4eea04c858b9f670100aac3847505fa578f145b2cfb669"),
        (&[0; 162], "9ba331a3c27c8451ab7cd00096b03307aa851bccb95dc81c68d47f0c8497c4e0"),
        (&[0; 163], "ef107fb441faf2a2389e6f7cafc34e5794f0f4ab4d9594defe8f16de9b8c1294"),
        (&[0; 164], "787121356e55b1e9d90f2ab8ec4ca290ee133d7f1a8177505a6970d5c1c45c2a"),
        (&[0; 165], "b26cf7b8241189fc0e21080899fcb88ff11b8d1e58eb1eded5db28ebdcb0e718"),
        (&[0; 166], "24c927280a75ea4c7438a323c1b7c63878dfb9a00a0558e85945ae0ffe2060c8"),
        (&[0; 167], "db07ad0ef0f61c3dcaa763cab86248c8e1cbb3e88c84bba0399eaa000dcca919"),
        (&[0; 168], "cfd23b6298abaea12ade48cd472295893b7facf37c92f425e50722a72ed084ac"),
        (&[0; 169], "5d0b56930da99d5297cea28620c999a173d349389a95f064b9431f315d6392c3"),
        (&[0; 170], "bdf8ba55ce1fcccd4a132b3a9b235f70d5044741d3f6b2177e684cd2f97f147c"),
        (&[0; 171], "7915843039e17170280702b7633919078b12a936a3bd2c3fd364192d3690aea7"),
        (&[0; 172], "bc45aeab049d47334c2a89515d147f0b00d49eff313d31986a6cdcc2d7374771"),
        (&[0; 173], "ea1c973ffa8b7c65435205a387b7bf407283558e7d8dd66e2b0c4485e52fa53b"),
        (&[0; 174], "77502376571d867bf70e1eae50e3baea34f04d8e9a6c190cdc09a81428b2fec8"),
        (&[0; 175], "b5eca1103c8c646550c8901a707d14b7909ec7b73d37160ff2cdbd0f69d2d0c7"),
        (&[0; 176], "ad13a76e82d8c4cfd92b915c95aef7c1d5de35c77a2a9ba765255a370718890c"),
        (&[0; 177], "4ac9e502cbaa0ffd0f56dae1532db4c6d138623cc4f1dc8d0554ace0b245adff"),
        (&[0; 178], "542b66fe7cce081d7583854534b9e0c656f807c09996be1fea7d137033caeb17"),
        (&[0; 179], "79062b67cf42529d74381929723661cda75de46a4ba4f16655f2c2d21bdc7299"),
        (&[0; 180], "fc827d59608a7e6007d7b900f6025f34ea93a09f1a373ea7735d6534ba731130"),
        (&[0; 181], "e914f8aff4d569a878ba8aeba3952ccb51649669f546fc1a63f72aed526fefb7"),
        (&[0; 182], "a9b6103d048e2ace82c19db41c0807f1f94deaa581e496e1629754cf5c02537d"),
        (&[0; 183], "02fcb93f9dcba28cb3dc0ae9936006070b03af38eb2b64972e6801d4775b53f5"),
        (&[0; 184], "3e080df6f6347136c2256a6c10f58421ffd587a89ad15fd5be435026d0b2a060"),
        (&[0; 185], "011ef57ebf6ae20f73ea5aed6a4e0380cdb55750a33e2675af2b817e4004e408"),
        (&[0; 186], "a5ca207a644d45319761cdc6fe085c6d010abbd0bff59cb90678eddab680d5f7"),
        (&[0; 187], "0aabdce5db49320c56a71e3eaa73f4930019c4f4d4f27b0237d2ba0c06c1c4aa"),
        (&[0; 188], "ebe877dc1c5a2a85dd6089e33156ed65691ff9b51e66df91ce0156365dc51819"),
        (&[0; 189], "785ea77dec5a8f92f2a76716538b2d1763c493f4aa9ede26df1a527eae82c171"),
        (&[0; 190], "2984e631b140867d5de4044435fe5b230e65b1620edb013c92ae18f6d6f34888"),
        (&[0; 191], "c58b669f59a238f39e8fa6414efe13c6d9f8da06d6e1cdd444ecad47ea0ebc91"),
        (&[0; 192], "1e990e27f0d7976bf2adbd60e20384da0125b76e2885a96aa707bcb054108b0d"),
        (&[0; 193], "24691b2b7a454835aaf9cbba5c3bd0fde296ab6fbaef0509050b1ca387f96727"),
        (&[0; 194], "1e67e5226a0ef760fe636a28e410d9060c6992961648daf110d0a4e8f649ce2a"),
        (&[0; 195], "1fa0b51baac7a59503da1cc2a1174ac5716dcc797ccf3c6258a69999b360a5c4"),
        (&[0; 196], "893b06229450f956b7bd800d3f20f4298344a010ed94f9c767f9374cf4004513"),
        (&[0; 197], "6d200bacae5b626ab61ae9a173f84ea622ff9b6bd95baeb9b110f40aa7bc64a7"),
        (&[0; 198], "2ba1e0ba12a2b54a119ced4500e28aa374c6fd4fef876ed93b3fddbb00369d89"),
        (&[0; 199], "46fc1b6eb2e8aafaa1b202a5780fd75315ad1eff92bb6298b61f5d2b6a31fe36"),
        (&[0; 200], "e1bb54e1bc3af48d01e5dbfc81015c98152a574f6428c6948aa4837c9c0baad9"),
        (&[0; 201], "d7e77a7492e6965ad38bebf43121250162dbbc71fa499e71cbcc426846e0755a"),
        (&[0; 202], "9dc41115026bf6c4c91abfd4b1a0ad2282159c6e7329e19d724b23068d103a82"),
        (&[0; 203], "5502b380473b61ea383596be9ec0a3b6f466eb6fdd0b3436d4dce34ecef8d021"),
        (&[0; 204], "b85a9c9b8bc315911b56d4b11ba1f0c6263a19f4b2b5672fa21b3a4cfc1b7196"),
        (&[0; 205], "a4c066e573d6093308f892b83a53a4fd38483505dab1ec97aaac38bc9e0854a9"),
        (&[0; 206], "73b7d529c54586bc74702cba288d0c8d3795e8e89bcc22b281814a85b800ef43"),
        (&[0; 207], "42c03068a617af9bb6e56281cc899e0a6718f486deda06f115bb4a5461023041"),
        (&[0; 208], "843d1213d52189dddf72d6ee9840ec21a1d9a6426d46c57f6ec1d3e5e0ca7ad6"),
        (&[0; 209], "f2e6f7e07d8e6012b59ffcf30b2cc3275ab36a68311ab1da079dfbf4b63a0941"),
        (&[0; 210], "e7adf6eee797e6ba5bfabba546c7eca7224072117d8d97a113bd595c241884cd"),
        (&[0; 211], "234b975424ce88bc269e70fb36dcf242d55de7308e4370a485ea8d7827ba6412"),
        (&[0; 212], "2c24684617d72eeed1fe10b42de06f1c6a19c0bbae49953d3951bf27204d912f"),
        (&[0; 213], "eea1b2d664c19b902ea74b63cc5166346e9ce4de1de41dd5b72dbc75709871a1"),
        (&[0; 214], "b5dbc64a5d54cef0c14da7db0a074712511b72399070040f71fe47eaad8fd6c9"),
        (&[0; 215], "f6e54fab4118a1c83d5e11c34295f8040c2e08afd4b9351eee585b0ccf47cd90"),
        (&[0; 216], "fca388c9e5a398293fb66c507fc1750176fda561361b921404c6a9e6de48701c"),
        (&[0; 217], "91ad829613402cae21a25dcfe58281bb00aca5cc23550fe7410a25007c45611e"),
        (&[0; 218], "74f64fa1975550d7f250d0c4f57177b8f7f4ad95e3fef8333671c56e706a22c3"),
        (&[0; 219], "226cbca20431694911f275814aee9dceda9ee09f8bca8f8ca104fa0c4a5eba92"),
        (&[0; 220], "88bbfb85921f63903957989bb891ccd3e46c77a76233406dd8c3262bd0070b45"),
        (&[0; 221], "13560374fa645f10cfd4c630535492877c014ff2ca6082fda9e871dd914ff08f"),
        (&[0; 222], "ee659e8c3f0eed6e06ec662d8ba01a1057c7d6b69da4f81018d6f16d930e82a1"),
        (&[0; 223], "18509b21f4e3a0d93eaf556395a7011d2c9cb2a3b2d3223fad91233cdea1960e"),
        (&[0; 224], "868e09d528a16744c1f38ea3c10cc2251e01a456434f91172247695087d129b7"),
        (&[0; 225], "8600a87a26ae31e103b9eb05708c5e4361f87d6fc824819258f69e26282aba25"),
        (&[0; 226], "7649892f2aaef966c228a5d4481f170012055c39a5a21454396e4d73238c5c86"),
        (&[0; 227], "58366165850e84e5cf09bebac34e83ab6b22de4b4b8182f934c2d6271e806442"),
        (&[0; 228], "5c9f6a0f545eae3fb962d2d461d6941a94bec6b063b0a64ac93b8cc5ac3adcaa"),
        (&[0; 229], "a09709ad9f2d64c9e9412fd3400e4b40a7232feebbb51ee7c61614c25b6df243"),
        (&[0; 230], "d8f682c24a0f0cb2bbcb8bbe883550cfa1daed4030e2c519edd69c108a90e5f2"),
        (&[0; 231], "046ea454470d5aa1981a26df34aec7a2a067d01db90dae59a08bd97c44aa0edd"),
        (&[0; 232], "0ffe3c6bcd792f447b3dd43283b24efbd8df6bda48bc540fd0d10b714b82d23d"),
        (&[0; 233], "6eb4b250153414bdd47e84dc4d38c884504fd34c46f9daa0f594eed77ccc1ee7"),
        (&[0; 234], "17d040b5613d09d662c0ee60158668defa3156f93c5ee4bb4f852a7a58e225dc"),
        (&[0; 235], "dcfdd1184be4e91505bc79bf5f552a46d613ec938983444833ea378c7e93dc22"),
        (&[0; 236], "1d961755b489ed475ac54072381a5132c45b2a668f0334f945907d76b4717e36"),
        (&[0; 237], "e6f8bbc1ab2733f039258873e2ff5606aa0db30e4f42201db3eee0172aafc8e8"),
        (&[0; 238], "85f858426529627afc4a7fa15b77ac1005e65318e2ddfed2f115dae501453f5f"),
        (&[0; 239], "a14cc0c1b312eeb4c84c2d07ab491a9d8c70378f827b2d42853be364c85b7fe0"),
        (&[0; 240], "02708857d826227fec94525f7e61345fd3a6e40fe25b4a4e1ced3a00cd4a665e"),
        (&[0; 241], "77b7a647140f09c65b550f8ef63a1c32ba93fa7fe44623053d6bf113bce90514"),
        (&[0; 242], "7d0e71d93e80699a75f2f0ae1ade2d21bbc784bb74b1f3ac9495d19bbe1f5bfc"),
        (&[0; 243], "525ae8f4a99e706b2a35d844c31d9dd5c2f55c3d0c7dd617d4efc3788bb9fb4a"),
        (&[0; 244], "d9bc6be15c19805fd2d7b26d646880608e48d4be519c3396e9e52a53620fbc13"),
        (&[0; 245], "c7ab1a2c3ca89aadaf698c22968a7c05d5bb03a2ab0a06ae4ed7aafb6b1fb45e"),
        (&[0; 246], "bf220830531a63e796485174a9c850f9277f04d952230238ab5cfba379dd58c0"),
        (&[0; 247], "f0966b2cca4ba5e8797c260817ec376d4ee43177f6ee58266a159a593792b0e0"),
        (&[0; 248], "c38c801df831a44b7cd3ac678135cfe58e8219857bc1edb6351017dc831ee6fe"),
        (&[0; 249], "ab0701e3ed87a9292ec2e0998ca8029b989d191029db01bbec8c8627d5271b49"),
        (&[0; 250], "e13fa46f2e07a6104dab7720c4820eb17a7395719c3eba8da33ecc47ba44c6a7"),
        (&[0; 251], "bbb61a5cb12cfd24eb9ce0d6d39af78ada46fc1df5d146bf53d1c5f21dfc653f"),
        (&[0; 252], "387c7b77b35ec95e9d8a7dba56ce45f6276dc56d2223bb93e1e792cf77086237"),
        (&[0; 253], "1d68d5569bbc8569b53576294c6905db982281625e3c3d54808e0a9c7a438194"),
        (&[0; 254], "fad21d780f881fd4f0b6855505b022a0a96b163e92c4eb996a181000e9d434f5"),
        (&[0; 255], "9b35a0f86cb17934d1598dd6ea522cc8bbfc53669da684cc6efd05a3dab9cb37"),
        (&[0; 256], "d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5"),
        (&[0; 257], "7a9efb4f2d5fc995fb0c798bd5426724a58aa7b05b62f646b6baed96f5dbfc87"),
        (&[0; 258], "efae27224674dceb1ac903a94241f0ee26f075fd145962fb9b49ded9b7849825"),
        (&[0; 259], "0a994aeb02c70f7346a1b6b3911681db3ff352a55f7c06272c930f470a69c26b"),
        (&[0; 260], "a23e82dff8aa8735826d2a61d87736290497eafbb342afabc1d6941120db1533"),
        (&[0; 261], "0f12344a9e8d263ee69f152c9fdb2e0c0d495592f1a4094ce2582c77c85e78b3"),
        (&[0; 262], "96237a9ac5918dd7cff2ac42cb9838967c1633ba5213a45efcc2bbc4bb30a45b"),
        (&[0; 263], "eb4a3459f2d7799979b98f781960470697cb2ddaa2d7acde8f1f3eba80cf4ba6"),
        (&[0; 264], "f6aae42d370617bd435d2ce1401018bf24c443bed6fc8ed23e5699485ce24f1f"),
        (&[0; 265], "fb7792009736a5f482ece8e1570e1eee3932d59ab75db1888efa27a8448689c9"),
        (&[0; 266], "97e017c3bcf1a9ffbfcd2b4e347cb4d3c9bc75a5260668335da6b46bd7888e5e"),
        (&[0; 267], "848263ee83ba763bf50c54f576f19ba158a03c953ff8651f90f91ad672e1029a"),
        (&[0; 268], "ab07391622478394fe6cd74b94df849de7e684258d5ceff7411a73698458767c"),
        (&[0; 269], "1b0ba1f8f3940626658abbf842337f7927f1ce353804eba91932dd8b42df30df"),
        (&[0; 270], "d1ba1135d558e48490db9c68601fc981e184cee873d98e3e62bc8ada3ff43017"),
        (&[0; 271], "3bb611e98ca876adc01436a582979ecfd012389033aca7dbf76dcb424fe02a0c"),
    ];
    impl_test!(Keccak256, zero_fill, ZERO_FILL, Keccak256::default());
}
