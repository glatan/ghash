use super::{Blake2, Hash};

pub struct Blake2s(Blake2<u32>);

impl Blake2s {
    #[rustfmt::skip]
    pub fn new(n: usize, k: usize, salt: [u32; 2]) -> Self {
        Self(Blake2::<u32>::new(n, k, salt))
    }
}

impl Default for Blake2s {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Blake2::<u32>::default())
    }
}

impl Hash for Blake2s {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.padding(message);
        self.0.compress();
        self.0.h[0..(self.0.n / 4)]
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Blake2s;
    use crate::impl_test;
    const OFFICIAL: [(&[u8], &str); 1] = [(
        "abc".as_bytes(),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    )];
    #[rustfmt::skip]
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
        (&[0; 1], "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea"),
        (&[0; 2], "774f9018b4b2cdc08f8928e89b0d963ac388e537b003492c69aafeeab976e553"),
        (&[0; 3], "ddc6305f977d3a21927ac314407a9e81beeab7f08deb6807828e234fa4641b17"),
        (&[0; 4], "4cd90cc0d54239ee5b3fd9989b4ef4cbebbbdd08410758cbd2d291fa364c82d5"),
        (&[0; 5], "a39dcf416cf4db86105cc01493f502943e36fcd6d97c9ca75daf90638485c4a4"),
        (&[0; 6], "5be21c4aee2f91935f1939075beffddcce6fe9e4173aa53e026d28b796bde136"),
        (&[0; 7], "2ac04a7276214582b4d88d3fce62c80988fc0244513a311c96a1676fa561c4b9"),
        (&[0; 8], "50dfdb12f464323c96af88ff5e8d90c5a1e7a04cdcf99d7cbcf9a271f08a766d"),
        (&[0; 9], "4ae15c95d4608ab2c5b3e32006d7c269eb1553eb5f2958022fa0b4523081c815"),
        (&[0; 10], "e590532145fb77e2b24b408f2c96a12b983007c756feae9400cc321b74a9fc37"),
        (&[0; 11], "6a6ceab781d9809b4a79a682b7093ecabeb0573e6385c3eeab400022cd69df77"),
        (&[0; 12], "2f837f649fd89f4a68e46f53f73ccd3fccbd9f04899f02d2ddef0a2e7b650375"),
        (&[0; 13], "1de4fe02554bfe37f69d0fe16e22221a6c418018dee52be69d60bd234b402937"),
        (&[0; 14], "0ba9ec1b2426c100b382d4801a9af39ed9cf0888e2336afe3ac60ccdaa642631"),
        (&[0; 15], "4e65bb875999af659bd75f41a32056520ec4b52b55a4a7ece1e8a58c098f0411"),
        (&[0; 16], "666480119667c204b51fc08730cc95ba7da1c333fed105df846e54cf0d0451ac"),
        (&[0; 17], "167b2f3446823e63ff50731cf4c137b0943921956ae31adc1f5666d542c87af4"),
        (&[0; 18], "fb8fd39064cf1de10b29ac1d7b9dc23d37b11901712bd1052d56d5ad752c4160"),
        (&[0; 19], "8bc9203ff21d325df39bbff84f177f94c0cb5f632814c94f8c3a54751a5a0aac"),
        (&[0; 20], "60a0fb302bfdedab7941d15fe4b41f12d33956811a110a9c7c06d0e4e7d2c97e"),
        (&[0; 21], "84a4932014cde6a7e7b88ed1f80b26cce2faf029c4c3a954ab55e17af30518a6"),
        (&[0; 22], "5f1f2a689cb1560cf0ec0c7710c3d67d51b287a0b4279415900bd3560985a015"),
        (&[0; 23], "491676c0b5b95e43ae5f2e870ac96a2e06138faf221d2b56d7e6286473315ed2"),
        (&[0; 24], "1032c4e37bf6cf095169c25766189389c741025d8f1573848db53ba484c107d3"),
        (&[0; 25], "0e0b3f671a12298308f0b8786e9f1ea9a719960a45260bdb80b3d9c955680c43"),
        (&[0; 26], "08b6cae864c490251beb05634062c7fab2c230c77006eede10fa4abfc313ba66"),
        (&[0; 27], "f5322dd90961ca40154172cd7abbf5e567003f0370cb47586e15ef3a9985414c"),
        (&[0; 28], "f275657938a19299a7bf039f0607322dd88c952d3dff74d5706105236289b0c0"),
        (&[0; 29], "db89361ef197b1e852b28bfca03146154313d93c4c2b031e67b1915a339b9b49"),
        (&[0; 30], "c4318c696fc1ca9eda50bd806cc0f14c902b5e3adf334f1b28af6323b53542c5"),
        (&[0; 31], "4b69cb57765bf40d2689105232f35d0750013ac1d53991860d5443019884aa60"),
        (&[0; 32], "320b5ea99e653bc2b593db4130d10a4efd3a0b4cc2e1a6672b678d71dfbd33ad"),
        (&[0; 33], "02dc1cbdfa9a150e0fc02f1e098f6f8ccdb676b95bd96704072bf52a9d93a23e"),
        (&[0; 34], "42d4fefdf55715972ad1c8d2d6a8c5a0f759b9231cdd56f9b51c2659da84357c"),
        (&[0; 35], "4a0f08e035809df314b547d4f01425085e5fec774796750d6ebfc69fa99ad70d"),
        (&[0; 36], "9c8963c479faadd8cacbf08a36a93d179465fed5f4ddfe2e42e62c97a1d7abf2"),
        (&[0; 37], "f9d4e359b6d7f9024baf556ed4d5b526a1054a5a67e787fceed8381f0cda62f2"),
        (&[0; 38], "3101807b4f487ad1c730d18f02af97229b7da83a5646c09b8e60527c6aba01ff"),
        (&[0; 39], "fb7e9e7e4114893698d5615fc8201c8085c48bb13ed4d21f77e49f4ef4054223"),
        (&[0; 40], "94bb15542026f4f607416f019dffe21bb39bbb32cc92085ab615660a6b5fbef4"),
        (&[0; 41], "a5b588bb5db505b1aea0bae0e0116156201eecbde868b466ff03661ac239b2a3"),
        (&[0; 42], "d18db82403f79bbae8c650f76573b4816bb9f31c0eeb5bb55fc4da72048af1e5"),
        (&[0; 43], "bb3b43d1ebcc3fd0e71b68a334a9d241ac7704447af92118250fb44668c796e8"),
        (&[0; 44], "f05462cfbb57657ad9d49dd457a36994f0408cf04d8ac14cfb7a6f6e920e7e97"),
        (&[0; 45], "410c70962f4592eee1f1191ea03e39343d2d3bdb3a6f0997bbbe112871ca6eaa"),
        (&[0; 46], "d3497ef0efcf6dd1e5a927a301e7dc6026ef235339a07ba1d339387afb15215b"),
        (&[0; 47], "2e544ee59454202bf24bb636997abd12e94d8f717434ef76b1ea38620c4feaff"),
        (&[0; 48], "f401874fee3bc5e1fcbabfba108e5b9a9950d45810190098aae7734e91a1240f"),
        (&[0; 49], "0e98f2921af88b8aa22b85000ba4fd6ae4c83b1ad067c3c6fb127336d94271b8"),
        (&[0; 50], "ce8d63f47ba72484b1e1817bc0641e0b09a7ceba748f6b3905bad2e55a222673"),
        (&[0; 51], "2324b2ba518d3fd93b47c6392eea0bb707b765bcb7006144dba1d8456bf0df33"),
        (&[0; 52], "06d119a50c3d93ec50dab8f733c7dc0a5cfb0d826d69f33d04b880445d2b599f"),
        (&[0; 53], "7bc5fc48546a478d3681de9edbd2c3d2247e666d07b42137fe82adc1534e72a3"),
        (&[0; 54], "2a01f1d2efb8001f5014e82502f10d197575bb3d9cd7a90344060042c1f8656f"),
        (&[0; 55], "ef90fc0f87eefcb19db2c62cafc318efa19a08288fa32c34b2d81585b4daf30d"),
        (&[0; 56], "1481ffc79bb06b35aa032d80ec384dc8cd38f03fb7f298441f85a30fd11ab67d"),
        (&[0; 57], "d814326715eaf4443bfd9cac9713322f34a06035f1b03f51b17c23e3a0ab0dff"),
        (&[0; 58], "13b3be37207a05c6a13c7a4b62e2534839d9ecd3266138d9fbb5fd8ed7e4e4d1"),
        (&[0; 59], "a1da72b25c59ca808810df2559388d6d5b6ba4e1b074ba9ebd9198ff882cb652"),
        (&[0; 60], "3c8ad387bcc798b1c5f788ddc0e025b835dfbea9da119b3600dbe36edee0e14a"),
        (&[0; 61], "e197112e436e99162cbb25953de4a677b939d2d4f2075fa137cc7f0f1b35d560"),
        (&[0; 62], "7e5ce747156affd77523f84b86982b1759f514e053488b5b3c5a025ea3f59945"),
        (&[0; 63], "d962856f3fcfaac80a84722012c38da68cce6b924a397d5a3db009babefdee61"),
        (&[0; 64], "ae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3"),
        (&[0; 65], "857328bf990b00922782d3e81c6054c25d3375d386c7424abe3e01d79041046c"),
        (&[0; 66], "c8ac4e7607a83655ac0580b6cbcdf171dd0d45dc68bd2ff02c96e37cb1a69d98"),
        (&[0; 67], "39e6edcbcc64ed70b6e86f4d64ebda0a41e0dc145e712289f6030888da30db42"),
        (&[0; 68], "21bc355cce7866c4d06fe512aaa64435d7f17a9f6491dfdc1ddf0421432dc059"),
        (&[0; 69], "a0df31cd00ed5a0ed34ca0fda127de68f69b83265250fe6413fcd72f21d565a2"),
        (&[0; 70], "493d66ab80403fd327e7b793fd74614eb399c22fbeb9dfbb6b86c084ac0c7ec4"),
        (&[0; 71], "5a9d9a79f61cd7f7c2efd8ee6c8aaeeb81ad1729084ac903f623da166d7cbe65"),
        (&[0; 72], "e3cdc93b3c2beb30f6a7c7cc45a32da012df9ae1be880e2c074885cb3f4e1e53"),
        (&[0; 73], "7c03faebc88e72db28b585091e177f6cec70e94d24f2fc2ccc6b550f2b32e366"),
        (&[0; 74], "17a5b8eea7fb6bd2ee9258d2226eb1dfd19e308dcd1064b20a6ebd7dff093cc5"),
        (&[0; 75], "e4f1bd9f3c48859e8d1475bc0a344421ef812d8a492625aec9cbf5eea44ecfee"),
        (&[0; 76], "747aab5abda97c98332e1ce3e9a288f6e12be4713fca2e9b77c5ed67d2fc3449"),
        (&[0; 77], "acb884d99573b6c764272e05bab9bd22c94d0e415d401e17bd4618ba4355f9b4"),
        (&[0; 78], "381931c35ef69aea00b634aca7af5067c9bc3f6444a069eb5c42fd17cd2d2275"),
        (&[0; 79], "397e540a2fafe52d98f6c0c934437361c22cd82c7fe0930d4784941b54f80f73"),
        (&[0; 80], "c4fde76a8d68422c5fbafde250f492109fb29ac66753292e1153aa11adae1a3a"),
        (&[0; 81], "6453a1a2c823ed7ea7aacd961c3f99e4f69eabb3281b9aa210819b643363101c"),
        (&[0; 82], "1fcb6a043cc8fa5c1b782c7b5d4d73ecb07a97b73d1a9d09250524d1fc03cd8b"),
        (&[0; 83], "85c0f01eae5f8608f50f0e28e714163224a17f7da3dbc892303da19d9352920a"),
        (&[0; 84], "f20b3508bb86320494f21332c81dfbaabd840106a4341f141ae053b1e732c2e5"),
        (&[0; 85], "aed0a307df71ebc79cb1ea61798d9ef624da00f03bb48f228affb7a9ba976472"),
        (&[0; 86], "c7e0f7fdc7ed9a30b14666e64ca2d62dcfcaebdd9c8e4b167d1ad93e66372d60"),
        (&[0; 87], "ff4e2bb011804932d29aab3957f3a9ea8e3e10cea69ed6cf354c5093f7871238"),
        (&[0; 88], "8f573863e3215bc93fff740475cf6f8878a16cffff6077539cd3bc2d398c62e4"),
        (&[0; 89], "067aac0fdb6a162139f584661367dd9b9845feeac54284b8d1f0388180bd0bc6"),
        (&[0; 90], "39427924bbc2ddd5fd47564fa416b25dbdcdb2111c6cc702c82e44e8c0f2cb61"),
        (&[0; 91], "8ec6a9ea64d63c081fa7f4bff77645dbe4d42f0c2350250df37768360b229a63"),
        (&[0; 92], "5eee0e5b71176ac930ef657e5ff2bc0935cf7094c7dbc5baac1d6f518407bb15"),
        (&[0; 93], "327be0cf83e9266e2d91fa764d3b88cb40f8a97f042ad4748c7afa767d86ced5"),
        (&[0; 94], "bb9a1e597fc1ed037b74741f1aa8eb89042b5767a4ce40e7ee161924c4d86187"),
        (&[0; 95], "eb1262de1d9ddd164328baff8f4efdc391c8cc4c576f7b978e80b6a7555b2377"),
        (&[0; 96], "452854105d05ae885c11a91d65eed176648d5aeeba8ca7ba27f9fbee0e4b63f6"),
        (&[0; 97], "8d8fd2b6bc4469114cdfb48bd5f0faaa1040d68a2992570aa30021ab21802cb0"),
        (&[0; 98], "f44a904fa79851dd86f65ba52e072799df78e099ffbeb1312a900c7f0390ef27"),
        (&[0; 99], "2d22987d41a4d702d0ebad72eaadc62b41c819dba2d0edea23f1263fdf8d8643"),
        (&[0; 100], "bfc72c20977f12fddf2791ade2595e4d6956f249fc175ccc684c3284bda84df0"),
        (&[0; 101], "c4ab68b73faa80aea2708f49fc99f131cce4eb08f3855ace006c647faaf003ec"),
        (&[0; 102], "566fb68b1fe279e2b9c2fcc26e18b878590c0e4c90bc2739a94d4e88fe73807a"),
        (&[0; 103], "1cc1e3d0dde4fac534add450df953e24334408204062f77acddd88267d17280e"),
        (&[0; 104], "eb41bec1fdbbca0a3685cc0c9e0e1c60cb66613a2a61cb4f52e08af929cbcd38"),
        (&[0; 105], "cce3b41c8120f4280eccb911416ace5e9cfcb489733031654a4d396f2cf04ae0"),
        (&[0; 106], "3b8c9b7a0633a9d8dacad0018ead6beb91ccbc19f3aba12590c47ffc9a371010"),
        (&[0; 107], "c26ad0331bef8ba6952b681c83d7e583784458f6626235161331fe7e7a4be3bf"),
        (&[0; 108], "9b62e50dff0f07e3975c4fdb896297f9e4428de5c02886bc0e80ae6117da3912"),
        (&[0; 109], "9af5e008d9fb1c1c53aae7cefc1979d74878fbc0b560bd7627a3befefeae4833"),
        (&[0; 110], "1dc7aad603865a0798790048e0f1ed72057ab369aa9981238ece6a6777e59c8e"),
        (&[0; 111], "516a77f29592b24ef710e462d68a06f04d55b5887d77193f25c89486a769bfdd"),
        (&[0; 112], "943a8ed79fd61f4027f19c70342d0fd55986602a8d449c43a9424b1eec8b6579"),
        (&[0; 113], "32737a5a3b1a12fe46c2eac74f8ae420903c394837832dbae80ef3c5a64e6941"),
        (&[0; 114], "b1bd9b4b3d02ce27f7916cc86ef2538ac6739dd626d08c83ed122fa0e2293c93"),
        (&[0; 115], "46c66503e633b2e63f10a095bab6b3cca1ce3a90e8d056e3fe9b9e0aa9e514ce"),
        (&[0; 116], "314d5b1baa03d630798d487371e5d4eed116c9159d04a7ff341bf3433e44fe54"),
        (&[0; 117], "d45dee108905b264fcc0e61331d6f3a16d9e984b3f7c85f4977d08c296bb553e"),
        (&[0; 118], "55da9280068eb1f06000955ab93b2678f21136914649cf768cf342e787fac96d"),
        (&[0; 119], "cde656a0c55a14f5fd3f97403316f73231e69f6f119805edcd02a271154cebbf"),
        (&[0; 120], "ce0afce96f10cc3530c114809a2fdd0855d7e09f0f855a57b9666376bd9898d6"),
        (&[0; 121], "1715e1e4c36f069d32213edc27df42e305a9e4ee95931f8c42552e2fa5a15849"),
        (&[0; 122], "410781ff5147d64475a5ba66867216d822ff11b8e77c0bb01c709edf26757b4a"),
        (&[0; 123], "826543dd3e8fe322a6e0e98e640764be3d206edf98efb553240280f134f1c6e1"),
        (&[0; 124], "7a2b5e8d3961f5c992b2fa0ad45881ac0873fd0dced3c4b9085b02879c8a02b2"),
        (&[0; 125], "ef7e5e0924a4a0d8c33b9531068758359f83aa9bdea9ef203d3849af364a1d85"),
        (&[0; 126], "515e61640ff3b28ee625725635e8a9ff636056ae8794ead3e7373640bb31cd11"),
        (&[0; 127], "301830ab384e3c00d5295e835228dfb68ff1a68e73c20a92da27353d7f654852"),
    ];
    impl_test!(Blake2s, official, OFFICIAL, Blake2s::default());
    impl_test!(Blake2s, zero_fill, ZERO_FILL, Blake2s::default());
}
