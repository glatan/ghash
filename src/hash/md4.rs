use super::Hash;
use crate::impl_padding;
use std::cmp::Ordering;

#[allow(clippy::many_single_char_names)]
const fn round1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
}

#[allow(clippy::many_single_char_names)]
const fn round2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    a.wrapping_add(g(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x5A82_7999)
        .rotate_left(s)
}

#[allow(clippy::many_single_char_names)]
const fn round3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    const fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    a.wrapping_add(h(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x6ED9_EBA1)
        .rotate_left(s)
}

pub struct Md4 {
    word_block: Vec<u32>,
    status: [u32; 4],
}

impl Md4 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self) {
        let (mut a, mut b, mut c, mut d);
        let mut x: [u32; 16] = [0; 16];
        for i in 0..(self.word_block.len() / 16) {
            for j in 0..16 {
                x[j] = self.word_block[16 * i + j];
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            // Round 1
            for &k in &[0, 4, 8, 12] {
                a = round1(a, b, c, d, x[k], 3);
                d = round1(d, a, b, c, x[k + 1], 7);
                c = round1(c, d, a, b, x[k + 2], 11);
                b = round1(b, c, d, a, x[k + 3], 19);
            }
            // Round 2
            for k in 0..4 {
                a = round2(a, b, c, d, x[k], 3);
                d = round2(d, a, b, c, x[k + 4], 5);
                c = round2(c, d, a, b, x[k + 8], 9);
                b = round2(b, c, d, a, x[k + 12], 13);
            }
            // Round 3
            for &k in &[0, 2, 1, 3] {
                a = round3(a, b, c, d, x[k], 3);
                d = round3(d, a, b, c, x[k + 8], 9);
                c = round3(c, d, a, b, x[k + 4], 11);
                b = round3(b, c, d, a, x[k + 12], 15);
            }
            self.status = [
                self.status[0].wrapping_add(a),
                self.status[1].wrapping_add(b),
                self.status[2].wrapping_add(c),
                self.status[3].wrapping_add(d),
            ];
        }
        self.status[0] = self.status[0].swap_bytes();
        self.status[1] = self.status[1].swap_bytes();
        self.status[2] = self.status[2].swap_bytes();
        self.status[3] = self.status[3].swap_bytes();
    }
}

impl Md4 {
    impl_padding!(u32 => self, from_le_bytes, to_le_bytes);
}

impl Default for Md4 {
    fn default() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
        }
    }
}

impl Hash for Md4 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.padding(message);
        self.compress();
        self.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Md4;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 7] = [
        // https://tools.ietf.org/html/rfc1320
        ("".as_bytes(), "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a".as_bytes(), "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc".as_bytes(), "a448017aaf21d8525fc10ae87aa6729d"),
        (
            "message digest".as_bytes(),
            "d9130a8164549fe818874806e1c7014b",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ];
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (&[0; 1], "47c61a0fa8738ba77308a8a600f88e4b"),
        (&[0; 2], "d4da020aedcd249a7a418867a6f0c18a"),
        (&[0; 3], "eeb121f19b8a3677ef8e05e83bed43f3"),
        (&[0; 4], "1b06b0037d44bcc91f0b2653e4e5ccd5"),
        (&[0; 5], "7030e7e998a77f0145014c7e4f117871"),
        (&[0; 6], "d4901dec5080745361508610870f47df"),
        (&[0; 7], "eec8cc70ac13cd2b277f984d2ac9517f"),
        (&[0; 8], "be195a9d98d55caa8f41b0fdfb0bbec5"),
        (&[0; 9], "025c9a1e8b6b6cb6af5ddcff5839f243"),
        (&[0; 10], "d2c2ff1afd684af8ad95126042d84460"),
        (&[0; 11], "45903f6ae6e05bf7c606cfe168243730"),
        (&[0; 12], "31086e9f791d5027d1f45b68821c3e60"),
        (&[0; 13], "456092e2acfd7ac14f1ab6e95999a732"),
        (&[0; 14], "da694af2440136d929db7d872b0f0f0a"),
        (&[0; 15], "373e9149faaeb7bf1da7a6c635728b6f"),
        (&[0; 16], "487c3f5e2b0d6a79324ecdbe9c15166f"),
        (&[0; 17], "cf3524fb41bc4c44a875473c92ea9a9e"),
        (&[0; 18], "1aed5f8d9de741214f0c88a081b76013"),
        (&[0; 19], "5a2ed1367fa577dd36f98dc246bdb4bf"),
        (&[0; 20], "d03ef7c4fe709c9586f33d65014b3f03"),
        (&[0; 21], "f901becf47337b96a2d64553592058ec"),
        (&[0; 22], "fc9cb6c7e22dbc69c06dd4c8d565bd0d"),
        (&[0; 23], "b65e549e9024565ec15d139a9a6c9880"),
        (&[0; 24], "56e3bb30347ddbb7ba4b92a091c98a00"),
        (&[0; 25], "712796751d490b8ada9764b2c80e995a"),
        (&[0; 26], "b02ced8f31f6d802ad5ed24031b3856c"),
        (&[0; 27], "c98604728a27ebdcea7b0a0cb0c51ed5"),
        (&[0; 28], "1d5b3dea3188687b8d3d15357cedb81c"),
        (&[0; 29], "ba8bbfae6c21bfd184aeb83a0be5bd64"),
        (&[0; 30], "6f0a7f7af45839f1e08b5be067e8031a"),
        (&[0; 31], "c2567fc047bfa582350ecaac7a567d8e"),
        (&[0; 32], "baeb6426823712722b339ed22b383fa9"),
        (&[0; 33], "ffb0dd967424d907919f32f6542592dc"),
        (&[0; 34], "4c317b5764819263ef6f3a3c13599da3"),
        (&[0; 35], "70568ed93487da1870c9a51cfbb2e3e8"),
        (&[0; 36], "1760146d0dde317e25913ebee21e33c9"),
        (&[0; 37], "3f26f1caf47972fce7146c7dcd9b06ce"),
        (&[0; 38], "32a7b2547cc0da3984956112011bb6c7"),
        (&[0; 39], "35d4a859ff576ca9f0d8f5110cfd2e94"),
        (&[0; 40], "2b3b667f60d89cb1d5b55a64a94bd75c"),
        (&[0; 41], "fcc361a26c9b1b8856466c7f7e138058"),
        (&[0; 42], "13216e009ff41e8fd58b29851faceffb"),
        (&[0; 43], "f324ed89c78f6fa5f6ea8a39f9536ab9"),
        (&[0; 44], "c5eb80cdbca9737a0db792407b57a9b3"),
        (&[0; 45], "763dd55ebe7542d8b1c5357872541311"),
        (&[0; 46], "fc7c9d1c277ac1456de73c4c7b8b0fee"),
        (&[0; 47], "faf7c60d49167a67894c8d22cc53b7d0"),
        (&[0; 48], "ffa5f599f07dec588e210404200dd871"),
        (&[0; 49], "db296aa7e8ce72aaceff45219a2c8e1e"),
        (&[0; 50], "65d025927adfff5af4a2b8f5771b2f63"),
        (&[0; 51], "ca8d961c71628ed66d509825135432c4"),
        (&[0; 52], "ab1eebd0245a389b89158d8b894e71ae"),
        (&[0; 53], "7e053c58b7d28554270865117b1a2717"),
        (&[0; 54], "56d2bcbc9dc84232cda1c8d3147e2b54"),
        (&[0; 55], "2df5a83f688f18c0866c64173be82a8f"),
        (&[0; 56], "7b9b4593cd9322ea492cf0bcdd84f0ae"),
        (&[0; 57], "5dccb300d28e7ccc7519db5dd15e416a"),
        (&[0; 58], "45f1d51531ceffde2117ef229980ef50"),
        (&[0; 59], "e2f813a8a83a5e98f39b8a5fc7e377fb"),
        (&[0; 60], "cd3abe7c750d6a7b88785ad0f0a33ca5"),
        (&[0; 61], "8a7d34cfc3494c45000f6efcdf23b975"),
        (&[0; 62], "2a1eaa5efd49ff285a8941d5d7b9f9c3"),
        (&[0; 63], "594697fc0810937e0e899a65911293b5"),
        (&[0; 64], "2f6f7b10c5cadca6d5770f428c899ba7"),
        (&[0; 65], "4fc27bbf517522311018663e59ced7a5"),
        (&[0; 66], "3cf88e669a841e0cd0aca026b68895d2"),
        (&[0; 67], "f822b49f8a678227b50a2a0e2ef66312"),
        (&[0; 68], "a0a6e456b03c291dceaeaa85d0ef2404"),
        (&[0; 69], "c5ec9eb070213c353e06c29fb99e6e9b"),
        (&[0; 70], "b7fb31c975f0cedf7cdec8d33bc27061"),
        (&[0; 71], "d8ec6e100e67c01011fed83bd04d5834"),
        (&[0; 72], "f19df3bb9cf1fa6ab9cf906fc6d8d4b4"),
        (&[0; 73], "f46741a770f111211a9c7afcab92c6e3"),
        (&[0; 74], "f9b6aaa6117649996d24d72498681e44"),
        (&[0; 75], "f0abb2298e4e8866ca458acb23c3d100"),
        (&[0; 76], "847758fceafc42d6dc968e022ccbcc72"),
        (&[0; 77], "5ddb2c5c81905947dc859a4e211f9492"),
        (&[0; 78], "bb1a1bb76013bf22a9632909195e5d86"),
        (&[0; 79], "b015d3019a4b721430f888f07e10eaf5"),
        (&[0; 80], "848d7c1b43abf239714d039b1b3b38f3"),
        (&[0; 81], "60c7b29ac7cb5cec789c37d895995738"),
        (&[0; 82], "5a61b126722b3424eb34d98c8ba0b97b"),
        (&[0; 83], "2f441ab8d9dfce5f109b4d3ef1b92a53"),
        (&[0; 84], "76cc2970d3d2777d094f6b55d8db3b1d"),
        (&[0; 85], "d72c1f9c620c0a99e8f31a8948e2131a"),
        (&[0; 86], "7c6fd0cc43f1bd04feff0f86b51b557a"),
        (&[0; 87], "81593ed09fcb2740119afd68e9be1937"),
        (&[0; 88], "626ff19251e85a6fdea08b7cfc8fe4f2"),
        (&[0; 89], "c48b812748fd84c7b4ae116c5cd24ce0"),
        (&[0; 90], "e0e1d24fb9276a052ac23db671dc302f"),
        (&[0; 91], "950f5f6a1fa4fe0ec4dc43ca91d306b3"),
        (&[0; 92], "5e7426da08b93f1be9868fa3043f1d95"),
        (&[0; 93], "1294eb50b627004786a2272340fe3297"),
        (&[0; 94], "460718f17f2c925c87bac01d83cf12f7"),
        (&[0; 95], "12c35e0cc690e7756e7311419dbd25a5"),
        (&[0; 96], "e6e4f4904deeb15ce385452c09722213"),
        (&[0; 97], "ae90838a1b7b35c850924c8d68910bce"),
        (&[0; 98], "885a8b7610285764659cf3271c2dbec1"),
        (&[0; 99], "0fbe6b007774a8e51463b79b8b7e6ddc"),
        (&[0; 100], "b450415cb857010dc4e169bcd0049912"),
        (&[0; 101], "cdcae1abdc28ecd05db43160be28b9bc"),
        (&[0; 102], "ed76c95fc52d7b38404a9d6b2beb0071"),
        (&[0; 103], "eadbd0025c26cbbf8fd62fa8bdd12294"),
        (&[0; 104], "0c5d2cafeea4ac6bf61c02a23cb55a0d"),
        (&[0; 105], "bec67a06d87b7b47d957d9c2ae31e85c"),
        (&[0; 106], "8c318631bc2dae5731d7ca74a706309d"),
        (&[0; 107], "d6af1fcbab6950e2d86b6c25427c0956"),
        (&[0; 108], "3c0d9e4f94f7145beafe35849ae011aa"),
        (&[0; 109], "a990de38a301a056488b62c2ebd0df24"),
        (&[0; 110], "04117aa578337c6ea3df3a6db35232b9"),
        (&[0; 111], "e783cda2b11a767777297ec14b515695"),
        (&[0; 112], "74de6b1dad70b5794d07d3c40dd7a1c2"),
        (&[0; 113], "4cab5e742474afc58f35b1f8aa70ec10"),
        (&[0; 114], "0d7f9d2096a625df741dc0248332659d"),
        (&[0; 115], "e7e56b768ee58429ba9c7ce4d25d26f9"),
        (&[0; 116], "98d01c38c64a0b007e690ac961c350ca"),
        (&[0; 117], "3d73c5db5a77d460f91833dd5a81a978"),
        (&[0; 118], "a59a744ee488e663060f7726c35d6ccb"),
        (&[0; 119], "8bf9d82d3cd1246ab64363d6da010259"),
        (&[0; 120], "888e0376839fc84239dba15a308df398"),
        (&[0; 121], "cf179da68e0ce51e24daaa0dfa132384"),
        (&[0; 122], "9a5fe2240768f7311426f6a415203496"),
        (&[0; 123], "d36aa3c7e1f37ceb8eea55d7e020d253"),
        (&[0; 124], "8d69744a4a59dbba5539814301e9f384"),
        (&[0; 125], "a51d0d693f0dfa99ef1d4d5366b44916"),
        (&[0; 126], "88ffd417318fcb5407926c993ab27873"),
        (&[0; 127], "37820edaf511c500017fbebad06d03ed"),
    ];
    impl_test!(Md4, official, OFFICIAL, Md4::default());
    impl_test!(Md4, zero_fill, ZERO_FILL, Md4::default());
}
