use super::Hash;
use super::{f, K160_LEFT, K160_RIGHT, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT};
use crate::impl_md_flow;
use std::cmp::Ordering;

pub struct Ripemd160 {
    status: [u32; 5],
}

impl Ripemd160 {
    pub fn new() -> Self {
        Self::default()
    }
    fn compress(&mut self, x: &[u32; 16]) {
        let mut t;
        let [mut a_left, mut b_left, mut c_left, mut d_left, mut e_left] = self.status;
        let [mut a_right, mut b_right, mut c_right, mut d_right, mut e_right] = self.status;
        for j in 0..80 {
            t = a_left
                .wrapping_add(f(j, b_left, c_left, d_left))
                .wrapping_add(x[R_LEFT[j]])
                .wrapping_add(K160_LEFT[(j / 16)])
                .rotate_left(S_LEFT[j])
                .wrapping_add(e_left);
            a_left = e_left;
            e_left = d_left;
            d_left = c_left.rotate_left(10);
            c_left = b_left;
            b_left = t;
            t = a_right
                .wrapping_add(f(79 - j, b_right, c_right, d_right))
                .wrapping_add(x[R_RIGHT[j]])
                .wrapping_add(K160_RIGHT[(j / 16)])
                .rotate_left(S_RIGHT[j])
                .wrapping_add(e_right);
            a_right = e_right;
            e_right = d_right;
            d_right = c_right.rotate_left(10);
            c_right = b_right;
            b_right = t;
        }
        t = self.status[1].wrapping_add(c_left).wrapping_add(d_right);
        self.status[1] = self.status[2].wrapping_add(d_left).wrapping_add(e_right);
        self.status[2] = self.status[3].wrapping_add(e_left).wrapping_add(a_right);
        self.status[3] = self.status[4].wrapping_add(a_left).wrapping_add(b_right);
        self.status[4] = self.status[0].wrapping_add(b_left).wrapping_add(c_right);
        self.status[0] = t;
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self {
            status: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
        }
    }
}

impl Hash for Ripemd160 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32 => self, message, from_le_bytes, to_le_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ripemd160;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 9] = [
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
        ("".as_bytes(), "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ("a".as_bytes(), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ("abc".as_bytes(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (
            "message digest".as_bytes(),
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        ),
        (&[0x61; 1000000], "52783243c1697bdbe16d37f97f68f08325dc1528"),
    ];
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (&[0; 1], "c81b94933420221a7ac004a90242d8b1d3e5070d"),
        (&[0; 2], "f7d50d120d655be4b88750873e00caf147f28a1b"),
        (&[0; 3], "a70793db403bd6f77df5b2fb91c16bad7d0bf9e8"),
        (&[0; 4], "a3b4245b511dab9f1a475d893355562d43e35f95"),
        (&[0; 5], "585bd7ed566208944b1f2e13170cd4b66325b8ee"),
        (&[0; 6], "13fb9c0a496ebbed86907b00c31eeb50ee4f044d"),
        (&[0; 7], "5c099d2fb8c015fd1045910c1dc76e27e13e5838"),
        (&[0; 8], "da5d81ab0f895f193adac4787d2aa29d064cf68e"),
        (&[0; 9], "f4b7fe5e9c0898fb14bf52365feece17d5047199"),
        (&[0; 10], "2faf22c04d223d51c92ccc16cfddb4e492187764"),
        (&[0; 11], "308cb7e6f38acaa3db0d085e9891eed617f4568d"),
        (&[0; 12], "d22456c75c3bfc4db75736e7add1471920dfe2fa"),
        (&[0; 13], "b458a1ee08980ca3b8bf0a4946fe020aced2ccb6"),
        (&[0; 14], "a3bd31e5e58e9050e8cad823c60c6ebb73e92c11"),
        (&[0; 15], "e71a56c3c854cb6c088903767c34a90b71d929fc"),
        (&[0; 16], "f2760c89487a4bf0d47f6ccca8d68915311a80d6"),
        (&[0; 17], "1c0fe223bb6c6e6c5ea61e266a2f95baa58263ae"),
        (&[0; 18], "9a7cd1b3f93dc5dee69bc167eca2c1cfdc409037"),
        (&[0; 19], "b4f0eb097a6c092ba07d9604de6b7314042950b8"),
        (&[0; 20], "5c00bd4aca04a9057c09b20b05f723f2e23deb65"),
        (&[0; 21], "bced605ce23b1c8e9da32569f061803fb08c630a"),
        (&[0; 22], "2c726747f3aa85252ec3ff9fe089f16ed5af2e19"),
        (&[0; 23], "58cf2dbcd5a73634cb89685f909651a275617be4"),
        (&[0; 24], "f9246dd2db040059cbcfaa163c364796cdabdc92"),
        (&[0; 25], "477ed03c11783ba2bde212121805cad3c262961d"),
        (&[0; 26], "877bb2fe45c59cfda8dc41fa500cd3e4f3f5271f"),
        (&[0; 27], "ea32a4df97ed6f93f6422c34ab92330ff11789de"),
        (&[0; 28], "9f6b07c7a6c0a3059beeeac9336ed11a2fad6235"),
        (&[0; 29], "a286155731ee1710cce82b2177c3a251924adddd"),
        (&[0; 30], "f444212b0c4f1f53616d9b8a7563b8c26151859d"),
        (&[0; 31], "a5f4407969f42e0cda5b997df86fd9ee07723dd0"),
        (&[0; 32], "d1a70126ff7a149ca6f9b638db084480440ff842"),
        (&[0; 33], "86e7b522eff410f32d3792afc4889fabcab40791"),
        (&[0; 34], "4060baec7d7540faae4c19f30ad1bc0f6114a0a2"),
        (&[0; 35], "2b482f6af8b8c5e9e3e34dec7017e867d2164d8b"),
        (&[0; 36], "353e0f80c3f9f6051294b1340ca1d71b81e5d77a"),
        (&[0; 37], "51d59f99254fc66d92fad3bd21894339777afda3"),
        (&[0; 38], "5afb442f1b7c4d165b26309e3931ceebe25c45df"),
        (&[0; 39], "2a9597be4ab20f69ce57c3504db6327b45617915"),
        (&[0; 40], "06557144f1556945b79eef2cb2e4c66c4541d17f"),
        (&[0; 41], "02c1824d8ece074431f8acbf5758b057d4772295"),
        (&[0; 42], "f316ee0390a8ded855c2c237437ef72dacccd2c8"),
        (&[0; 43], "d93a7bc17144aa13981039d61ba4c69a19406a05"),
        (&[0; 44], "5481c97625618d3f74c26967b8ab209ca7fedf9d"),
        (&[0; 45], "17c988e9439ea0fe33ff5cf9ab593d909bf880fb"),
        (&[0; 46], "b35429f9e9eb9a4aaab151acd8dcffe7962ff8a6"),
        (&[0; 47], "79cb983ff725a973a6613624fa6500a038aafee8"),
        (&[0; 48], "4215498e71967e250d0a416361b6f478e7c1b429"),
        (&[0; 49], "c68294903ba22a64640483c6a615a0c4cc30bc85"),
        (&[0; 50], "4ebd91bc72ae5673bb9f6611da95c340bf376802"),
        (&[0; 51], "9886acc86d8d9c0747995bbd98c166bb374d06bd"),
        (&[0; 52], "387ffde64927ef0aaea6156f612d67fec2083529"),
        (&[0; 53], "9e4fe75460097fa7b3aa94d1782a390c67b24034"),
        (&[0; 54], "7d84ed5010251cd80b5c7610df644060506dfc3a"),
        (&[0; 55], "e323d78db60afc7404def79abb82b8fb73591037"),
        (&[0; 56], "7724d7cdbbe24a75a58958d784e3a325ce0e9c7c"),
        (&[0; 57], "60e5ca5387c9cd6093aedeae1ee18e0fd5b9cfa4"),
        (&[0; 58], "5608a60b1ffece0da52f35b02ec1cf80eba1c549"),
        (&[0; 59], "1e52cca170c1cbd4d33bc58e93b1f9af3483b47b"),
        (&[0; 60], "aba7ed34bce59096a05296704a14ef11aa9d195f"),
        (&[0; 61], "e51fbf853cf9418a0dace4162292a9ff643a6ee4"),
        (&[0; 62], "73a9a6af1079b29d8f48db593fc1d387d6cf335f"),
        (&[0; 63], "898ce0102e6090a253edde87bd6e025b7a6dad70"),
        (&[0; 64], "9b8ccc2f374ae313a914763cc9cdfb47bfe1c229"),
        (&[0; 65], "ab3c66cd0a3f12b4f4faeb548a55160794fad706"),
        (&[0; 66], "0d02e945c9b301b2190d9f7bb2d74b7df7be889f"),
        (&[0; 67], "e68351305a83fcde3e316d4a2d0eb0158bcab973"),
        (&[0; 68], "7c5c05d337862c8b1867eabc5257ed2edb8a8aa5"),
        (&[0; 69], "4c5ed9fafa583969f01965c346a91571342e9508"),
        (&[0; 70], "2f45374035a1cfbe0b219a231034cb6fddb291f4"),
        (&[0; 71], "7125fcd9b9479ed63a641e26d8fc325e8e4da958"),
        (&[0; 72], "97d4a9a8059516fef77899424fd566f224e30f5d"),
        (&[0; 73], "07795ff21a6f6f6d41243460fe7e2284f78548da"),
        (&[0; 74], "0f8681925bbac391b51c82201016877cbc5afec0"),
        (&[0; 75], "62a639e1a23e4a51e3e5d5f5d5e29290c4f1ace5"),
        (&[0; 76], "fd1e5b14fa3ad4e454d5652d88f6bbb9a0dc550e"),
        (&[0; 77], "86584092cfa90991033323459d5ee7dfff19fd3d"),
        (&[0; 78], "b67a68dc3799d68a73883d465e8820d98352b0f2"),
        (&[0; 79], "fae871a3fdd02a49a7b810d765730431786ad223"),
        (&[0; 80], "c4f9f3dedab22ae5957309a6f2e2982ba314564d"),
        (&[0; 81], "2a4938a2551a7ada590074036848534ee22173ea"),
        (&[0; 82], "a54f38650bacc7cae0835986c2b57c8e3150df01"),
        (&[0; 83], "67d1f6c98ec227e52818c503390744fc171bf3fc"),
        (&[0; 84], "d630e994e4b529e438e39ea0df58449fe25e74b3"),
        (&[0; 85], "5c751fb4d6d69f9581b4d249a88ee5c28dd80b26"),
        (&[0; 86], "aecb6814f4e44e7f672b53e76da14514d17c2ad3"),
        (&[0; 87], "9f44222fb84cd753f6d318d956afec110da6d7bc"),
        (&[0; 88], "d8a24eab1e312211e923808f897ee2fc50893562"),
        (&[0; 89], "060833d07f80b83e24cf44428af562c7aa1bb634"),
        (&[0; 90], "e69584c680e88412611dffe47d2204b29e81f338"),
        (&[0; 91], "7212edd79875763962a6cc640bd05b18e3dbff37"),
        (&[0; 92], "bcd57839ecf7deace35e8e8df54eb5652d98cec9"),
        (&[0; 93], "55e3e45e297340d825931c2f51294e6fd8726a36"),
        (&[0; 94], "e3ff3cda773e5782459a3797385fab564aa2b632"),
        (&[0; 95], "d1ffdaa306f0788c6571788e5698fe2f77429566"),
        (&[0; 96], "c018774e0aabc6d9ae19b8885f715ef2939c0f7f"),
        (&[0; 97], "c45f69dede531191eef53ab099f6595c8f7995e1"),
        (&[0; 98], "1e2fcdcc73586c20dd36eb98de06db7ce94509aa"),
        (&[0; 99], "c639639c8322448b1d3f510c2264c390cd811835"),
        (&[0; 100], "16113715ec6304fd651ee99de637d4bb6ff11f19"),
        (&[0; 101], "12e8eeaf41fa1cfa4ba919ded922a998018c398b"),
        (&[0; 102], "92219268e8d5888618ac461993302a2a90dc90dc"),
        (&[0; 103], "1b97fe6a94e292c57f184e76f1685bfaae68b7a0"),
        (&[0; 104], "fd5accf8ac32f310715dafb6f422d08d1ddcbd57"),
        (&[0; 105], "50a23e12f3e8bf17eb72317837e48222f7fc0f3c"),
        (&[0; 106], "bf7e5af2e139c062e8a0bc63e35f62f43a160c9e"),
        (&[0; 107], "5f72ef0193c868a89f1c7086b0be85dba8aed116"),
        (&[0; 108], "8c4f091a8092979fa5ed5e0642f2aca4a2ee582a"),
        (&[0; 109], "d7d4081cbc1931351fd1eea47002e1eccc136ea5"),
        (&[0; 110], "28005ee7ef441cbcab9eb9543d7f3a74e641d376"),
        (&[0; 111], "bfa5ab2308a8a92889f61a95086e976467b863bf"),
        (&[0; 112], "269e414d5f309531ac745c9cfc492f5e04a90614"),
        (&[0; 113], "fed4b3064166e436d45ea59d8df4096204d2961f"),
        (&[0; 114], "96addf37a5af302177e03384e48f6a0cc3b79bd8"),
        (&[0; 115], "0d34abf9dc3dc945f9a953b22ccd554b6d54f004"),
        (&[0; 116], "6c9160997513b4d254e756da62fba12aac712008"),
        (&[0; 117], "0dcb6c243428fc3f776912f60e5c8feead73eba9"),
        (&[0; 118], "769ede73f7de501afa69e43e5b0a5374618c2279"),
        (&[0; 119], "acca99d26afd854a971929871b6632a28eceeb27"),
        (&[0; 120], "0adadc9282e710827d41f349b3e688efbc6c6512"),
        (&[0; 121], "a073a372e094aa77d535c0bd1216107badc226d2"),
        (&[0; 122], "8ae06dad14bd0d6b1f5f0b75a27880db297e48cb"),
        (&[0; 123], "1e96ab0f8df7030c8b4675418c42965fae2c94ee"),
        (&[0; 124], "7ae21c8f8111879da5486f913a69d3154a263da8"),
        (&[0; 125], "a8c6fef820f0220dfdb0738385409d1ac57bf0d3"),
        (&[0; 126], "de6ec50bf6cdbef67e355e5a040048c36bb55ba3"),
        (&[0; 127], "869b242118756440ae73cc65cc5797aedaf08f62"),
    ];
    impl_test!(Ripemd160, official, OFFICIAL, Ripemd160::default());
    impl_test!(Ripemd160, zero_fill, ZERO_FILL, Ripemd160::default());
}
