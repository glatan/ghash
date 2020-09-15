// Keccak-224: [r=1152, c=448]

use super::{Hash, Keccak};

pub struct Keccak224(Keccak);

impl Keccak224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Keccak224 {
    fn default() -> Self {
        Self(Keccak::new(1152, 448, 224))
    }
}

impl Hash for Keccak224 {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8> {
        let mut keccak224 = Self::default();
        keccak224.0.padding(message, 0x01);
        keccak224.0.keccak()
    }
}

#[cfg(test)]
use crate::impl_test;

#[cfg(test)]
#[rustfmt::skip]
const TEST_CASES: [(&[u8], &str); (1152 / 8) * 2] = [
    // Generated by reference implementation
    (&[0; 0], "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"),
    (&[0; 1], "b7e52d015afb9bb56c19955720964f1a68b1aba96a7a9454472927be"),
    (&[0; 2], "5a2b171561dd59dc4a0786ee1ea5b8564abdd25c58b71ce1b40bd9a6"),
    (&[0; 3], "f968db079b3da0df1aa4c147fcbde89b507429b95e2550fa99141725"),
    (&[0; 4], "f493445f6430d82ecbbd16d2f96ecf459352aba2038b6d4a7d0b09a5"),
    (&[0; 5], "394635e05b48a5adfa529c77b49ccc12eac4dbcf98250751fafb9a6c"),
    (&[0; 6], "371ae97d06238165973bfff7883d843739ff3949c9b8d9af0b309c12"),
    (&[0; 7], "1ce88001db6c713ead257ab924ae0c6e1e285701b6c2a94163b7c907"),
    (&[0; 8], "7f5596b0268011f30ee275ca9b96e0a497095e7802627efc0f203c11"),
    (&[0; 9], "6940cd4aee2547bfc2873e8134b77e72475ed30cc3c54b1f8583001d"),
    (&[0; 10], "e662299d6e5bd0771066cd96cf3784044f0f01e5ed2d3d826cc27308"),
    (&[0; 11], "32ff6ef4220d8a7738834da9810c5f254676ad3e60819de8e004bb26"),
    (&[0; 12], "a30e23c5cd3dfc0fc57b73400cb45fa807ce974ec548146f53a20b3e"),
    (&[0; 13], "1d181bead58e8d61eea4e06177571e9c15ebdc2cb8cfb6f8b8bf00cc"),
    (&[0; 14], "eef0b71d8751520b230cf93cf5f9a3740f40955e517238ea51a28513"),
    (&[0; 15], "965527053451b80aaae127607b4e88fd14126f8b89f6c738d0e75c04"),
    (&[0; 16], "83af6e911a3351a828cbc8ff80622b0675252382baf6484a11120c16"),
    (&[0; 17], "ed89a68e60c70b8b579c3fe7d87867d0c3f37caee8b8d583bae38b74"),
    (&[0; 18], "a8e2d5af69cdf0819a41998a2a16f866f2d83a17a166bc9c8150d99c"),
    (&[0; 19], "80da1f1d81da3325073b8ad5ecdaafe8e4d3664efa2e140f72ae9d2f"),
    (&[0; 20], "5a51e1e458d8d40de723bb1ca99136a1024cc9b687ff3275dd6605a9"),
    (&[0; 21], "7326dc2c0c8ea2679ac01e6eb777a4f84121ef233ab21acb093c96be"),
    (&[0; 22], "a553aa8067e9a56a4830ded2631cc281d2361e5e16289fcd1eb87d60"),
    (&[0; 23], "619dfac9964e794a652c318b8d3e805479ed2fdf70b84dcc20e4bfe5"),
    (&[0; 24], "535a70642871bdbc3c3181a01091bf9661aecc707a234cd2ce19f9ea"),
    (&[0; 25], "e4dabd716c36962de76968ec4e6a94b2de5a75314c86255968bd319f"),
    (&[0; 26], "f30b7c490563a415efdcccd4ab48817d26e30370482f40e584aaf394"),
    (&[0; 27], "79a5f0473eb4e9319420908d716f8a14031d724faa7dc48c83c55182"),
    (&[0; 28], "d11f21684943f0f9b4537f15c71e7afc8e7f20568aabac4866c78a27"),
    (&[0; 29], "8b0c4296ed08db6de83a78781b59c3cddb60b2ef05e06bef2f4ae83e"),
    (&[0; 30], "d1d0f896f6a80b9449c3f6010e12aa21e13698a1a7d4f1294246ab93"),
    (&[0; 31], "9d665106a1c2e18e07882f2d93999dfc919a2b4f0b39321cec7fede6"),
    (&[0; 32], "a5eaefe1e57893552823dfeb754c8014a60431840a8ab3e25aec93b9"),
    (&[0; 33], "9f320072b2c2ae5ecf5808dcc0bae77669510cb796feb6c6d76d8662"),
    (&[0; 34], "6848c1b9ac3b08044cb97fd401564256e9c1c97ba7a0066237687e51"),
    (&[0; 35], "7541d7cb8525d10b8d6b2bbae480aab875e8ca34ca1e097196d8b95e"),
    (&[0; 36], "4fe147fa9ccb0622964fb2d1de21c94a2a3266af4e486c7ecded7ee8"),
    (&[0; 37], "715a0111a0b677b6d1b63ece548d6cac3a7161673061aadccae5bb53"),
    (&[0; 38], "6736300a962f1301a2fe54e6ba9ba07217d96de698ddb8589df3b3b8"),
    (&[0; 39], "18282fc82ee97e6df424d7f2f1d4b5b2161e0a46032e094874c26567"),
    (&[0; 40], "e03007fac4db52172e2a80efbd9c715afe1bc63c1719d93619608a80"),
    (&[0; 41], "820fd8767e17a1aa08bfe0cf7f59a3d2155c78eeddb08f7e8077531b"),
    (&[0; 42], "688e166a2521a2482d3040c9b02b9f35c92a3ddc1ea7c9a348d9fc6c"),
    (&[0; 43], "e151a7c6ab061cd6cab106f0a38837d1963202d642cde59bd05bfc68"),
    (&[0; 44], "c147551761e5e6402d09530241ec2ff1d1fedbeb2c5dc9c6866f4469"),
    (&[0; 45], "fb31b58fbf7a386645cabb8f095b83ad034482e19dfc807d86135a91"),
    (&[0; 46], "11b975830f8cfb6c09e1309f7b018e817d6510406579823073454c97"),
    (&[0; 47], "51eee7de8335c26cb15eeebbc6e86189a9c00909063aacbeaedfe407"),
    (&[0; 48], "51027c4eb1d077a07e022d75244018f237635671c0e0966716432207"),
    (&[0; 49], "d5ea42e64a446f61efec0f157ddeb7fbf77df5c1f1582e836979861f"),
    (&[0; 50], "7e7ec60e974f2177a3f3ad06db901ff5bde75a0a83b356479e2ffe1d"),
    (&[0; 51], "32c052324167f057999ae8ddda18bccfa91c4cbbdf03bce865b9e55a"),
    (&[0; 52], "fbe9a0908ec36ae7a1b9c221a857d5b51182e2b4e08e79910eb9e065"),
    (&[0; 53], "e3a8dcb8bdd81b1ce9695dbe7e615ed551c4a671b5799b148a61daf4"),
    (&[0; 54], "f10386973e3f98011c840e96432cd8e96417f92bbf000210d2ce6a74"),
    (&[0; 55], "a6abf680b20d88370e3118fff8681e38f8a84601b8129f99ecffe274"),
    (&[0; 56], "4c53783c92ae75b68e760087ad64083e08678b5a4325f575f5439b8d"),
    (&[0; 57], "ea5ea8a66543d10d24a6c7b7eddf7bb182f4a78b4aedff1c77aa99ec"),
    (&[0; 58], "822c6f340276369fa802d1d8d509490bd85667f1104b9cc626f17fcb"),
    (&[0; 59], "e5cdf47f6ffe7d66dd33b012477ba8cf33f268f47401fce0e54d2c01"),
    (&[0; 60], "3c84295bd41a6fb386772cddae86af9630dbd23442a80b8df37b1b01"),
    (&[0; 61], "a5223806a8d3704fee1e816ccb9d3d604385d0ef7b7e3c0f649c1010"),
    (&[0; 62], "fba88558bb22772dab2f6d5a30faed9944bc9d0c320e11369a93077f"),
    (&[0; 63], "2b4bd02083f2d6964a12fc220e944f9d70080d426b2d3579160c083f"),
    (&[0; 64], "f929b0f8227e2eab822ba6e0be53af25c75798b0ee2cb4d5b0f89b4c"),
    (&[0; 65], "beb520db63dc034d7384371db93da76eb1000a7eaea364dabb21778f"),
    (&[0; 66], "e590e55dde4c2a17464e2e1f65e872ca6f95485df52897662ad72512"),
    (&[0; 67], "47fc5974887ca438c44bd37f324cd3d64544e6b454c01185226b3be3"),
    (&[0; 68], "ff2c48b2df32be2f25f934d4b3d6aaea20e1730ebdc6bc783ceb136a"),
    (&[0; 69], "9049d1963825fe82d2f9e607e80690cfd29ff3dd093533be1907254e"),
    (&[0; 70], "f7d13e26d60ad998f9a66afdcea76206fdb6169b3e31a46fbbed85d6"),
    (&[0; 71], "403faa9a79aeb8c5214b373e06e561a6b4dbcd9b114a7ed64ccf3837"),
    (&[0; 72], "097ebc4aab53df78f6b2e65cfd7d09a29ca85754eb88a7e8fefa3be9"),
    (&[0; 73], "d1f6a1ab8a401c1d86b6b19c0eb38ad295e891a6e080ac61fcd24cf1"),
    (&[0; 74], "77aa4d07380f2f26afe3534c8762a7cf284c20d3e9b577c1778d82c9"),
    (&[0; 75], "a1144c6c9f773b5f025135b930808bcd8b6098686af2a08508c8c632"),
    (&[0; 76], "6c1bcfc4061c55815920fead6ef6f2a742373e1bfc337574249f0a86"),
    (&[0; 77], "51cc0a019ee1140991207fc5ba048d5113309e6df25c7529356a48b3"),
    (&[0; 78], "0ba1ef5083c7819c7eac56a426a3e46fd16826bf81b4baf5fcb489b5"),
    (&[0; 79], "16faa7077ddc4bad3ae755bcdf0df9581173f1ad3f44b9265b08596c"),
    (&[0; 80], "3b2ef52e1126eacd3bae10ccf504594a3507017227fd6f5e2fa832af"),
    (&[0; 81], "595094994965b4ffb56f75865141e054b66821c735552fa427236bfc"),
    (&[0; 82], "347b26bddf793dc579f7627fc979550c2b6fc32e32c25556417511ec"),
    (&[0; 83], "584ef7a4224530fc2be6b55b4d7f2aac3041f0b0e8a1f31fcba0dff0"),
    (&[0; 84], "f5f59f5e0abf3dbbd545d67d0056357ab10239316c5e432c5710f587"),
    (&[0; 85], "eb04dcdd21f3cef28e2c0ad928483a9734dd119b68cf65d5defbd07d"),
    (&[0; 86], "e85d35b76bc1276f054159cfcadb2ef1ca9754b8e706e3a462360655"),
    (&[0; 87], "ba0022817dd88ec1cb40d70d527a00965c484b581244fdc181127808"),
    (&[0; 88], "17e9ac3baec776a4cfe52c45b09af1558c8ae2f66efa0a88cf6e9c1e"),
    (&[0; 89], "d94744663f7f7d9840b7feca0264b319d1fc4b39d146be8b0ee22ab9"),
    (&[0; 90], "eee09d419d6c65b00f269abf0c839df30f81f6d3aa7dc39c3cb94448"),
    (&[0; 91], "c89cf4b4ef0740b68fa54b2d56abe6bf26f990eb6f3af1a2efc6b6ae"),
    (&[0; 92], "7a1992c85f55379c4ad9aa9c76730c6d33e7421cd86eab062f73c63b"),
    (&[0; 93], "71c0b0b602dc787e4609fb9360442cbd3181d4280fb5ab4c7f10d145"),
    (&[0; 94], "328d92a8b16f058f0d6473864f6e5992d6f8df7e803c1bc997b0a5e3"),
    (&[0; 95], "899f903ca42e7471616b698898f5f463787cf115bf46f22b39a47fdd"),
    (&[0; 96], "16abba0eaf59aeda0c5e3334f8aa4ae0187774beb91d9620d8c3cde2"),
    (&[0; 97], "038c7783e7cb82130b3157b0b56d71f28bd9062c847718df208ddb50"),
    (&[0; 98], "fe7bf94d528000a8d8f0da320309265f342e2fc4b74044065c747fa3"),
    (&[0; 99], "2b949a740f11bfc19ab286039cc500fc90c06cb546682161e7539447"),
    (&[0; 100], "0014971e3949bfaa757b1c28191713bca6bd6ef92c306bf12d1d426b"),
    (&[0; 101], "55aa2b1997169ac9e547d26ea1bedb82d4858e5e3ede88c76998160c"),
    (&[0; 102], "76697b741d9276f4e982da21b4cf0b8cd49ee9f5d8314c8a867eb464"),
    (&[0; 103], "0e787dbaa28dc285b511d58812474193470da69eb1f327a994116ad2"),
    (&[0; 104], "98509da30d5c17f000b0057627ee4a785d3c2da76df26f6549e48630"),
    (&[0; 105], "bac076fe385dec41e8a86634c149debd7438f4f3e889e80e97084063"),
    (&[0; 106], "f643e58f0fb85cc3b0e880b1fe943014c76b1ccce1459a05d5fccb59"),
    (&[0; 107], "fb0749b9c39d61bbdf86cc9ae7d7c49c560c7d7adb71e234bdbaeb97"),
    (&[0; 108], "10c7a92450ca729cd81f60f1014c4637255f1598aaa85590a24bcf52"),
    (&[0; 109], "5f0584c99e98023ff786b02bc6817c4b0340dc94de7c2369c39c7c4b"),
    (&[0; 110], "2be3a21bdb1d38ef5b0d8682a98ab7176efd3feb54c129b84e727ca3"),
    (&[0; 111], "3435eb633de742060aa1ddb052d8075b5a4cfdca8a13c2b7b0ee42f1"),
    (&[0; 112], "3bd9d56d0e1ee76bbd7d87f830bb97471a53be8a79ffc7e65e8cbb9b"),
    (&[0; 113], "bfd449d53f589919a64710c7ba1a602c6ad7b472ea21cf39d220005f"),
    (&[0; 114], "2bf2f9411dc176dc70288812f8fd51ba5c99fec7efcaceefe1fec612"),
    (&[0; 115], "ac685aaa1b5c49df25c7a9f5bd6c1725bb65e631e6b9825e86e920d9"),
    (&[0; 116], "abf9c85ca37a0692af048cbbb7acd0db6fd54424366321e92fdf6e4d"),
    (&[0; 117], "30aa2ce2e193b54ab9035de96a4db0b5d1efdb4cf42b2f9638216b6a"),
    (&[0; 118], "85e287667c54463d15dcb2439c6f2e2d37658e79548f3221cac6a0aa"),
    (&[0; 119], "c26d5ccaba48ba54eb383e547775ebfaab9af5c8cd5fd0f7b10b1108"),
    (&[0; 120], "c76395b54e0f328933d55432fd052ba9fb6bbba4860cee6ac62fb127"),
    (&[0; 121], "56dd8fa022b292471240ed13d2416ed5d5fd169dc70d619b2841b617"),
    (&[0; 122], "70800f2d0a65561438fd9cf2d9b2d6268ee3d3d9085b64747874dea3"),
    (&[0; 123], "905ecda9287a129d23089b61d7af8ea0d2de7c9ae8a21d80b04b6ae2"),
    (&[0; 124], "8395294046cc931359724e1a95a01e3886e2e642fda15b57b7a2fc78"),
    (&[0; 125], "7e88b378c988d7493cbf6e5731ef90fab9cbd264d6161cf8fac34708"),
    (&[0; 126], "0a905ec10639824244be8acec3ca51b1537cf01fbca98f3f9a0adb49"),
    (&[0; 127], "f407767dfeefc180ab96c12d6e69d991c4a3086ce2e628e154f891e1"),
    (&[0; 128], "9c7f54b7a29dcd912e7bf7003325ed228ec7ac3e1d61cd1b61fb94c0"),
    (&[0; 129], "d6f6ecac49def6624851037a922ed1e18a9bb798bf01793f8ef8458f"),
    (&[0; 130], "04dfd1d0e8a4acd25c107bc59acc8cff16253abb7397cbc5c0991884"),
    (&[0; 131], "60e8807ff96e922b644b47024b88eee9a1f0788873c7c98f9b9c71bd"),
    (&[0; 132], "c4ec82233a76bf6489bef24d12e763c8c34f5209e27db49ab771ccec"),
    (&[0; 133], "c34d301fc289b38254ceba98bb7f9dcc03636504f2ac9dde7b4b6cea"),
    (&[0; 134], "d05186139d8afe27ada8f4451d0a36a449e4bdfa698a38ef71f000c1"),
    (&[0; 135], "5b320065ee2765e07ac11d86041808da319461ef3dc7b99c470e4be0"),
    (&[0; 136], "2ce195ce389a731b6fad92e8a53d67bc744c63b4795db817047febb5"),
    (&[0; 137], "9931e0a0deb94ed43c87dfad14ebfcc0494cf7925e2d3a7d219cbfa8"),
    (&[0; 138], "e125d33dc29326e4b28d70f5ba7f74f75285003fb8c065dd09b7b3e1"),
    (&[0; 139], "0972ecab8644c197bdbce6264c2f658c5d3f021e2b76ceb03de00802"),
    (&[0; 140], "9f1308dc461c77c61030a5ae62917bb540c9ce39d0be1d87a41848c0"),
    (&[0; 141], "a75dd33bcba1168aa86e3046d9e1bdf454690e0f8f419752e6b0a387"),
    (&[0; 142], "239d5a93eb3f5aa25276cca32b7c3967f61a72cf7b61b89c637f341d"),
    (&[0; 143], "265901e55dbe342660a9321b172e6e6f39ce9582cf5a11a007611669"),
    (&[0; 144], "a50976d8ed54c961a052bfd01a64cd79b11928a9d5b75146a0828888"),
    (&[0; 145], "5147c62d05b0ed7cd7e62934470e5ade1fd43c7707d95c2f8168cae3"),
    (&[0; 146], "e4b5a040f5fefff99ae1ce915e0a052a28ab043f77d4007d334984b3"),
    (&[0; 147], "dea904cb11a64924d93391cb2ffc1dd6dd047423fcb4912c6d33ed2c"),
    (&[0; 148], "2049310b95f088beba78c5552091cc2e84b7c5f868a30aea6596ce8c"),
    (&[0; 149], "abaea1d1efa97ee6efd32764c3a5d6ff6ae8604c0a05d112c8d56624"),
    (&[0; 150], "2386f89c75475ffd03a790a000fa6fa66532ab64c37d3b0d47114b4c"),
    (&[0; 151], "a00c5ab836356aeeeb1b7a3a4028009ec8aa294807beca42240da257"),
    (&[0; 152], "b14e18f3eee8591b2d986dd63d66bf31edbd484b925bfa11bf5a8763"),
    (&[0; 153], "fec16052ad466ebf49f4de29ab0716d53b333bd468e33b4610325273"),
    (&[0; 154], "4384ab1c8a1bcafe2749016e0c36b34f04f939886a1bccdd63b393b6"),
    (&[0; 155], "1604df2031816ff75d3dbd32b4922d1d409a97b2e13b4cc129f66a09"),
    (&[0; 156], "3f520fa3395d218d9d31de221927b9f6d74f6dca111d4fb19250125c"),
    (&[0; 157], "d0f4ae6bdcdf9621b7cb2122b5de2130f5cab6cd35a73122d72e7641"),
    (&[0; 158], "7beae04bd642d337bf3bd8d7872beb312bef414b2cb03a1026e715eb"),
    (&[0; 159], "95cf6abaaf8265da875e10a1fe16740d2996cf3fe94ac5fcaa8d17ae"),
    (&[0; 160], "73f9108b3771c6bd59b2d44e7e7826dba9a76af5092c27d841082390"),
    (&[0; 161], "10ad2e4d3352edfeb3afc11a025754947b459062fadfec2e5f3470fe"),
    (&[0; 162], "88397ce5900d9b49180c85ff026e520deb1fd2d8d9ba85344968bb01"),
    (&[0; 163], "581d435c081595eb022f6ddd86d1d6d12439941ee86f2d662079b35f"),
    (&[0; 164], "673614fd7d8b8255bda08b9b2458453da4d31ff39b177b8640b25670"),
    (&[0; 165], "66c9d71c0dcbd01d85d4071baff5337fea5be905cccad433419759ae"),
    (&[0; 166], "b808889f534e798cd0b8c1bb7653bb4bbbae54678a8a8f9554870356"),
    (&[0; 167], "062ce86955a92f9285345f67612e235fe0a157f79505e2b13bd672b8"),
    (&[0; 168], "665bd2384f143017317621be2c8d06da60adb1e57628e328142b9d2f"),
    (&[0; 169], "0070ba62be404bc96d02fa564a96698c2a1a2311f5e9389d04a57450"),
    (&[0; 170], "a3cfa9a3f60e1e8e618c3c6de223c4663f21b020650be031faa974e3"),
    (&[0; 171], "1a6b8d678ac8779001ed9b157bd7b5dede64eb5f62cdebd95e77285e"),
    (&[0; 172], "e47862f75cc6e7e4c332293cfb2b3af92132765f2ff6a795319158ed"),
    (&[0; 173], "0d93848b4def8f6552a9e36b3f193e9fad9f273cbf852cb2b3b0e1b6"),
    (&[0; 174], "17d5dc6476802d2446827256bc80290cb26f7430191e19bb51d6cf9e"),
    (&[0; 175], "04b93a8a8f1c4b9a4257130bd2ebfaa1c7b2c830322c87252350a452"),
    (&[0; 176], "0fbbdccd06baa72356984d0d40b4ae8c1b112b994e0ab82eb9e4679b"),
    (&[0; 177], "3771c482d1a8febf72adb81f1d375908d2c456911b42924518fc62dd"),
    (&[0; 178], "ae3ef96449480830a7314606cf60df308e87b03bcd3b915443db9fdd"),
    (&[0; 179], "d0b13bd276163440c301f80e58d8d026f475fee7d1ded17542f7700e"),
    (&[0; 180], "e621930c575bd1e4c9768305d63606a4510e6e5f4df5d33290bfe811"),
    (&[0; 181], "5ee16f334d31ed4b86f9e24b1d48724a0208c1cc35bc395020ab6b32"),
    (&[0; 182], "a4c9c8b7036ee13720703548583023ee4268aac09d3615f71b1b12ce"),
    (&[0; 183], "673b0c60d9496e396db84986c9bd2a033a7f97a4902a8a04e5f352ad"),
    (&[0; 184], "06af0ed5b6055718cbd5e2eb82c8e97d2f19d8285272323c360f17d8"),
    (&[0; 185], "839560ca9f8e44212292604e6317426d8a173e4e1b179b7cdc1f82f8"),
    (&[0; 186], "5e4567049d3e21a56e4b6e4d2e133592ce4c3aefba7f42abbfe02678"),
    (&[0; 187], "cf1d320bdffc786fb6bf924e7f509e971cc5f4d900cd9f319c81d6fb"),
    (&[0; 188], "865770c62f0592759a71601edde7d2fdc42414e61c641c3f8cd49b3b"),
    (&[0; 189], "244d7409e98cf9f56ea06c285e7da38cbf264c4164cbe070b682e624"),
    (&[0; 190], "69bc4e5b57be98afd744b1071b441c869f8442084e0c09e0400175d8"),
    (&[0; 191], "d00d0f8902a5fb2c0158178f3354bece845af284f90cdff89fef6857"),
    (&[0; 192], "51d1cbaf87739e2a2b72b71371bec86911a2417eab0f326b07f8be4a"),
    (&[0; 193], "a12c7b2ee47484d876de13b1e8cfc3a66547d8b1fe422ecc8951eb9c"),
    (&[0; 194], "9df6cf1a2e2a64d59f2808d1bcf43c28fc83ada1d65ce8e3452d7719"),
    (&[0; 195], "d3f15708901925772ae6e4c5adcf7c391cff7fa142484d7bc722e7fc"),
    (&[0; 196], "cc1ea36efe05971455d32977beba246ada35368305d36d2e971824ac"),
    (&[0; 197], "d49dff39346878a3c15b0be8b7722ead6b1b0691009032077f93b33b"),
    (&[0; 198], "30783ad22c8bc9e0208887da5c9bf7bf16789e678eef155818f2ef37"),
    (&[0; 199], "2fa719dd9498995a262b603b4df04a7df9ea19b747e3a311a94b813b"),
    (&[0; 200], "81537a168b56098ed312c79b3e1fc772ae4cacb168cbf8005a54d91a"),
    (&[0; 201], "6b6b0b42f054cba08d51ff20268c2f2156b1775ab9bf3d9c5366bea4"),
    (&[0; 202], "9ea19946e0511cb693cdb04d44c9b4113f674a8df1f50a584f256521"),
    (&[0; 203], "ab7ab31e96c6890212f923602c8a8290e639dac1d653c0531b4a6610"),
    (&[0; 204], "19d3ec75a6f3aa10fbc9b3cc5266df032fceb5454d7cd1323938fad2"),
    (&[0; 205], "763ce0f8030f53686ae5495fd265d2e363753db7795092c3a6a0a65f"),
    (&[0; 206], "c56192136389b7c31cb4d70f5ad325bd5d195def2a714cb12015cab7"),
    (&[0; 207], "8f99bb0a0084db93c90e55abc9460302930db91cda664b1c05c63b02"),
    (&[0; 208], "66d1bcdd4ca4e48e83a11ce92500a74a8ac52c75b1a213c71a089a33"),
    (&[0; 209], "0eafff9e74c51b61c80b62f63f1ce48cee187867f1e1171436f1299a"),
    (&[0; 210], "adaf8869ff41661d2a3bcfa179167737d95607f30fa938708f06cdab"),
    (&[0; 211], "45ba72e853dfab26e82ce2fa142357f5e14dcb2bf9637b3adb84d24c"),
    (&[0; 212], "7d00e9f9ef62028b7925e4c26b89306febc5eacc9540b41e41353407"),
    (&[0; 213], "03a3fec98b494872e33dd1f0a826a7b851dc814cdd6ef8142e6506db"),
    (&[0; 214], "660a78c99e3e035a70246e4f2cc73890a3615cc247ca1009b88123a8"),
    (&[0; 215], "2525df6665b8d068eb441680062a3f5ed4a534dbb26082aca3bfcfcf"),
    (&[0; 216], "d6cc2db39a10ee9993c98fdb8ef8b8209c9a346efe2c62955c68e439"),
    (&[0; 217], "7a71877d6b0eccaeafb2b869bfacbf9e6b06662cea88f522e9c93690"),
    (&[0; 218], "1a9c7e4153ebf4c3b15766654fa514e4308e47b895151b1fbf0f69e4"),
    (&[0; 219], "ecaa757bfde73db3ec83cdca5ce98712d8fde46e0137a75113141f2c"),
    (&[0; 220], "64029731f0804c1b2da5fdf87a0edd33dd2b1c8d6a6a53930aca7b4f"),
    (&[0; 221], "c330d7b74ffdfd95661b3dd036b8e78f25bf52fad4a7517f28b1cf72"),
    (&[0; 222], "7151f8588916cb9d5ee9b4e33047960dc2152ecc86e07cf3eb92f8d2"),
    (&[0; 223], "7a1b3a5dc93f2a57ca26479a00123af4c9c75bf11926e325de088609"),
    (&[0; 224], "32d1aa50434ed5082cfb109bc0e65390fd4b1c47c321241bcfbb7f7a"),
    (&[0; 225], "6db631d9119c5ea8660fba39978f10c8acebe9a09d5db00d057c797f"),
    (&[0; 226], "706d3a665bab11c518660a8b1fe008f21230cbe1a23720a84ed9414b"),
    (&[0; 227], "d1c39fa676005ec3ef53f603ee1330e2a0553196cf0a7028ed759f36"),
    (&[0; 228], "1555e9eb9a8e671f8c667e680bf1c670579873d01e9846aee0f0b740"),
    (&[0; 229], "9303e9d9bd42ae8b7dd8f7fe0267b4fbf78432c209ae2b128a13b9d2"),
    (&[0; 230], "fa6c44ac6e8dfd007721f317c7d47cbfbd032cdfebb84b8bc5c26658"),
    (&[0; 231], "94f3d63b1c03a4a43427f2c2fe7d6a7e727e54e1102808b1bb75a7f2"),
    (&[0; 232], "c7e0bbe9225950ea94cfdea7abf55468f678fb11537e66e00dc3c9a7"),
    (&[0; 233], "63ab91c5d4911a994979359451484c4febd3b7d6c20af9f565d50ff2"),
    (&[0; 234], "d67bfcfa88afde22c20d193eb1bdd8ad04a70b6acae4ebd10884b169"),
    (&[0; 235], "131826f29e9f45f33808e94f990b28210617469f6e18fa47a881d322"),
    (&[0; 236], "dbe299341200687bda10f3c7940771ad6ced473b07916e0944d2d353"),
    (&[0; 237], "1069a6a9e0f0358f53c5d32e18f931333b41f2d1da77b5c0d1824634"),
    (&[0; 238], "3e4b389ee4039b2413c5100edb6844598faf1ead232b398e43bf0f7d"),
    (&[0; 239], "a949efafa43ec0e7b8b33c58dd305d29a00c915704c0b23810a512c0"),
    (&[0; 240], "7726811c555c2aa6cf83e182ee263451d785f73a664d8cfd94ee320b"),
    (&[0; 241], "8a7fcbb6aff23cd75d1e6b8accd1c0cd53f7da6bc20809d4c49c2dc1"),
    (&[0; 242], "2b61b2a5299308b3597f4d29ab0ce0ec22df652a4807d335af4c239b"),
    (&[0; 243], "8e7e0fc4ecfacd058fcb035a854d44fa49c9bfa58a3b4aca05779441"),
    (&[0; 244], "2ee7d88105d8b78075e13cf3116352ac1d26e592c7f00077d29d1712"),
    (&[0; 245], "7e475355f164082c47b7bd289d26df9c0228748d22448e8cad7a4b95"),
    (&[0; 246], "c9bfde6ddfba5b107d91042b1f5e8aa5596b6ceea1819cddd50a5af6"),
    (&[0; 247], "4e6fdc9984b1aa3c740b5029b32086b505f874c98689b16eae19f03e"),
    (&[0; 248], "87c5558568d9791ee337776b69f85df9504a7b84ffc5aa3d3d7f67af"),
    (&[0; 249], "d4965bb824c4beece7660644f22e3ea23549006373c52b62916250d9"),
    (&[0; 250], "0d884efb24554458abedb731264dfd56b19954f539adfbbce9620aa5"),
    (&[0; 251], "1756fbf6280a62f77d2fa40999d9500c60b468955625fe1aa130efa5"),
    (&[0; 252], "7f36c4d590d5b5fed9427a568763541a0aeb63e4213c29aedbaadcc4"),
    (&[0; 253], "bd3a9ae1a285506f8ee98c54300ada5dda38980940cfc1eec2399317"),
    (&[0; 254], "1bc0838ef85c72eafc46fc0c6964cfac466c351be06720288e25c2b6"),
    (&[0; 255], "e0629a9ba131ba59b30ba897bc4ca54c91243b48ccef404ee6c18727"),
    (&[0; 256], "fb0afcc2a9b785ff7c698e32219be54b1e78c321c2fc643f1d2203cf"),
    (&[0; 257], "1f83ef68eedbd06037d53b6859d17c31b9ed0789443a9fd926e79cef"),
    (&[0; 258], "c79dd8e1012d19b437369760eafb69b4bbab73421365b9d3403ded1c"),
    (&[0; 259], "b90fb25683de850da81ff1b4ba53975cd741a7deb70d323020d72955"),
    (&[0; 260], "36f1d8027e9142064612ccd3f02271804e0af7ce326f8edf2ac088f5"),
    (&[0; 261], "251daef56c01583996e16a7f5c7c102542f9eb10afbbf51051c3f6b5"),
    (&[0; 262], "2d1857e21ec7466436e9af7d2854ca235918968f899e73759af43a79"),
    (&[0; 263], "abf6ce020d5d008ab001a7bbf791f9553e34751f71352d2d86106bd5"),
    (&[0; 264], "965b573085d375876d756aed09cb7bc55622e706cc409563ea675b05"),
    (&[0; 265], "8fa4567d08f71f27d4d958f61ca94c0bf357f31d5d5d725d95ca6226"),
    (&[0; 266], "bea5c7dbd639f38da57992fd19cd800140930d0d19d742c54802c45a"),
    (&[0; 267], "d053d965ad69d770416d4ae4d6003df41932b6141eb7a77e26a84188"),
    (&[0; 268], "cfdc54b46148c37d379e82765f129ea3af095fe64f2adc394b9ed95b"),
    (&[0; 269], "6f018c0e804b08523ee7dada1a51936959efd840fa3f3a94d389939a"),
    (&[0; 270], "15a822c34271b8def2a33299980c64c53ca5dbab4c6be121fc37acc0"),
    (&[0; 271], "087c2ed1869a7c58faebf999bc9a80ba9ef05476ab217ca298702e86"),
    (&[0; 272], "d6d4027288e94ea9b792639462da14bf965b44777e02a2a05f79da26"),
    (&[0; 273], "bd2e35f2b4daca7282c1f83c0117b1dd7668707b2e7b14d48ec54cbf"),
    (&[0; 274], "26d4999ffd9da70b15b8495744663361070b6ae07919db07c5467b35"),
    (&[0; 275], "8304b55d1c8ddf2d841b92d2ed820903a405cd53d2d14a090b555164"),
    (&[0; 276], "bdd1a475feb119c7b4466d73f4c66a8b838d94576bc5df14133a7191"),
    (&[0; 277], "f79037aa5c930ec6c79e74ae591fbdcdcf9c77ee3ebe72fc8c4cfe47"),
    (&[0; 278], "c4788cdb24ab11326157db6daad92c9d07c16b16478581a16b569a7e"),
    (&[0; 279], "8fd541f818079f6053d4ae83c232291eed51948d35db74f5949b07ed"),
    (&[0; 280], "987b2a7cdfcb60e69a8548ef20e5ba2345d7d79c0a7d652085d2e5c6"),
    (&[0; 281], "92f35cecf763a532a7c74227b34b6c151c9eead96d1a47eb595a9e9d"),
    (&[0; 282], "a26e6eba34e9dd11b4e2fdbd1470eb466c8816d6287b0dc55e16a4b2"),
    (&[0; 283], "f73573b696dadac1e7655ea4f48c6641dfa453cb4e32ceb8614e7ebe"),
    (&[0; 284], "2d05e17102f252e56ec5cf66d5b380eb4ff913617b8a3cadf0a215c3"),
    (&[0; 285], "332cfdee675f48291677bc59eb2cbee94a31e2371eebf446a0ce102b"),
    (&[0; 286], "4856a02dcfd1605d6edc3256b63b011c6612768e450e28188c53059d"),
    (&[0; 287], "3a4843368a3aa9799a38bfbf4510069728caab6aa5a0a0b022521cb4"),
];

#[cfg(test)]
impl_test!(Keccak224);
