use super::Hash;
use crate::impl_padding;
use std::cmp::Ordering;

// K(t) = 5A827999 ( 0 <= t <= 19)
// K(t) = 6ED9EBA1 (20 <= t <= 39)
// K(t) = 8F1BBCDC (40 <= t <= 59)
// K(t) = CA62C1D6 (60 <= t <= 79)
const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

// 0 <= t <= 19
const fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

// 20 <= t <= 39, 60 <= t <= 79
const fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

// 40 <= t <= 59
const fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

pub struct Sha0 {
    word_block: Vec<u32>,
    status: [u32; 5],
}

impl Sha0 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self) {
        let (mut a, mut b, mut c, mut d, mut e);
        let mut temp;
        let mut w = [0; 80];
        for i in 0..(self.word_block.len() / 16) {
            for t in 0..16 {
                w[t] = self.word_block[t + i * 16];
            }
            for t in 16..80 {
                w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            e = self.status[4];
            for t in 0..20 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(ch(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[0]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            for t in 20..40 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[1]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            for t in 40..60 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(maj(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[2]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            for t in 60..80 {
                temp = a
                    .rotate_left(5)
                    .wrapping_add(parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(w[t])
                    .wrapping_add(K[3]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            self.status[0] = self.status[0].wrapping_add(a);
            self.status[1] = self.status[1].wrapping_add(b);
            self.status[2] = self.status[2].wrapping_add(c);
            self.status[3] = self.status[3].wrapping_add(d);
            self.status[4] = self.status[4].wrapping_add(e);
        }
    }
}

impl Sha0 {
    impl_padding!(u32 => self, from_be_bytes, to_be_bytes);
}

impl Default for Sha0 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            word_block: Vec::with_capacity(16),
            status: [
                0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
            ],
        }
    }
}

impl Hash for Sha0 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.padding(message);
        self.compress();
        self.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha0;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
        // https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
        // https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
        ("abc".as_bytes(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
        ),
    ];
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
        (&[0; 1], "c6e20991c4a5ea747fdd7a9e3ce5210504a74e75"),
        (&[0; 2], "67b52e33a03be46456333aca5040a7e188cd3e80"),
        (&[0; 3], "ca96570b04e82a7076e83101a19ec1d76998f9b4"),
        (&[0; 4], "d4ec9cbbb502f007ff075101455f207523fed4ab"),
        (&[0; 5], "96e8a3e2e5c0220cde48ebec35b94304ae873867"),
        (&[0; 6], "2a91c5b50d1b5af5bbd980c5f929b354d40f27e8"),
        (&[0; 7], "db7ae93d4af6e41c385bda68c00f0df87cbba404"),
        (&[0; 8], "1a4ff977fbbaa583be5c1e2a143f2aeaf6ef89b1"),
        (&[0; 9], "856d68811e76130f3b222768cba1d6674e5c533b"),
        (&[0; 10], "2bfbd96d949458e654feea1b9531211a21eeb902"),
        (&[0; 11], "bc23b0f19c97850964d6a24243426a1285bda98c"),
        (&[0; 12], "225318432e7ad16ae8e7765a8c748bc7a3e2bd30"),
        (&[0; 13], "3cc9edb074c4be42430f943fedceaf232d2c2053"),
        (&[0; 14], "9e4222b136b7016c3fc751d4769ef431ae1f6963"),
        (&[0; 15], "29922371fc28d750f18599844e5d47c94468cb54"),
        (&[0; 16], "063fd2124cf36b1e13a1d0e75e63e3bb02100a56"),
        (&[0; 17], "f8130564912e3c040170d22a320b2ab70d5e5305"),
        (&[0; 18], "13a1cd7415972a9db9ccd8675b1bf64d4f98d4c0"),
        (&[0; 19], "7962891a98947397e999113355982030e5605776"),
        (&[0; 20], "bf31b39eceba076d00a4661bfa5864c959ecef09"),
        (&[0; 21], "0bdaed438bafd7ae8fc291a3c6715064128b85d4"),
        (&[0; 22], "19a9913d04088df160f00ce1aad4152c927503d2"),
        (&[0; 23], "36a976b044c9ff205a6ac786e2b888a7c6483316"),
        (&[0; 24], "0700e7b229ebacd4db42f92dcd02c02dc3d0bdad"),
        (&[0; 25], "5639117e4f20e0f8c4e4a730c2129ec4d454d04a"),
        (&[0; 26], "e1c610fcc9f632591c7f5e0d6210c254c5818215"),
        (&[0; 27], "57185efeceef44274a94a1c19f627ce9dcc43848"),
        (&[0; 28], "3e785c7f9470795c42a4ae4c39f19f59777d7adb"),
        (&[0; 29], "9df549d8b5a2e23a48610877fc0e8bbc16ccf0ce"),
        (&[0; 30], "754d7e9b828bd616cc784088b2c167bf6c24deb6"),
        (&[0; 31], "921fab7eea5c12d2f427db6c7691ea5a734609e5"),
        (&[0; 32], "7c4081b03b025a6a514e94aa8ae28e2d1a2c7f9e"),
        (&[0; 33], "b39177515e2ddb4d6e0de83c4ab5daa73f197095"),
        (&[0; 34], "fe3bd280d9a2b06d5ab5dac0235cbafdbfc9284d"),
        (&[0; 35], "8b7d48b88936fc56b77d3adb9e68a7b59384ed71"),
        (&[0; 36], "755e967c96fe98035eaab930a835940e9ff0a061"),
        (&[0; 37], "83dda0f7452a1480cdf4c8d30bc147e8619b0ccd"),
        (&[0; 38], "58502b510a5a3bd243a4b1fa06f197455b066098"),
        (&[0; 39], "a6590342f29258e878ce80052bc575bf1eca605a"),
        (&[0; 40], "e2e915012be62d393e8d117958c15782b43b9a4f"),
        (&[0; 41], "bd3d86b4219a3b0e2a932a93769df83a2682e77b"),
        (&[0; 42], "9bcf33c9c6c2b2eb17182a569f8ec8679762f267"),
        (&[0; 43], "107dfd99fd255abc366497cc5f7e12896851eeb9"),
        (&[0; 44], "92fe3db2869bd918f8eb22512c10adc54854296c"),
        (&[0; 45], "07d506eccdf8e8279da664ef4bd7f2bcc898ec24"),
        (&[0; 46], "c0a3c891f919e7ad5c50f3407f4719d54a7b53cf"),
        (&[0; 47], "f0461a7f8fae41e0eb9a141dd70bf213f7750908"),
        (&[0; 48], "a96addd4749bfa6ea1c1cb895bcb7cc32c83e766"),
        (&[0; 49], "96eb5230241be46aed1bd08a5450c7c0ee49f4e2"),
        (&[0; 50], "a9b9b514d6cccf6c3dac3766b68fc6e8b49fdb7d"),
        (&[0; 51], "7df41be078cad9b83786401235af2d4d590fce4f"),
        (&[0; 52], "d9b370057f4a7f94dc2a779367fd46640886da1b"),
        (&[0; 53], "cb31fe23931d7e85d8ee17a27d3fb0b9af2fa87d"),
        (&[0; 54], "724b786601e0c8d3a54304f83abf389e3bc2503d"),
        (&[0; 55], "a7b4948ca30db1b82deb813034bfe79caeb5b48d"),
        (&[0; 56], "ec0ed516ef0d30a95fbe425a686dc60b6804fd20"),
        (&[0; 57], "34cd99ee170f230a4c5e3215223cb33aa63a91d4"),
        (&[0; 58], "89706bb28bd8befa0a77c3095b5f2deadac8472c"),
        (&[0; 59], "18014a80d66ae9fd70c4a0239f7816923c24dcb8"),
        (&[0; 60], "06104328fb5b4e864e1318dd3d2f1a97b12c2ac1"),
        (&[0; 61], "5dcf85959cf6cb3fde7c97fbb1a765c423ae6bce"),
        (&[0; 62], "855d08e8fb359d28b4ec3026255c4d6b43cb1104"),
        (&[0; 63], "b4b811c387edb0830068978fbb96cd23b99e6c43"),
        (&[0; 64], "e7d2105da9833fe19bc2535d9da7d43f279d2f6f"),
        (&[0; 65], "0b03ca28d78b16255f9868d3311a3901c8df3e70"),
        (&[0; 66], "67b4e6d1b81d8bcea895bf20aa52c86d0a48ed49"),
        (&[0; 67], "e9b664cf8425af0925fd1dbf3aedd961728b0b1a"),
        (&[0; 68], "fa2f977f73bcd1c7db415e07fe53e2be14f11e1a"),
        (&[0; 69], "6856bdce9268ae3a61536a6484fc7992fa7a7cba"),
        (&[0; 70], "02e71b35558b99b4affcf11101168a298719164c"),
        (&[0; 71], "d73ccb9bda2116d3db84f43d8fdd3108febf747a"),
        (&[0; 72], "6847705950ea243ec7cca79a32889149264e5eab"),
        (&[0; 73], "fc121c4e891ad5d2b427b1e7ec926b4d1408ab79"),
        (&[0; 74], "4e1deb944e892b25ac019e5f0154a7a57a4baa1a"),
        (&[0; 75], "9addcfbc2162fea4de4f7f030ec354f2c6fe0fac"),
        (&[0; 76], "9ea01bcdb38ed8285b25343144f4b965dbbf9013"),
        (&[0; 77], "bf46dd7aed6a91dd314cff4093c2af0ac5b27c0e"),
        (&[0; 78], "e9a1f9a5329ec84c933cd36bf5b8e6ed93e3809f"),
        (&[0; 79], "36fbe8deab13e14ab9385241523b476a4ff3b6d9"),
        (&[0; 80], "a473b655d8ab0ed784b4e5102978c5609e947d93"),
        (&[0; 81], "ea2478a7b638089472e66dc21a3344048706c548"),
        (&[0; 82], "d6ec9d57226885c02b2205b92f40a1998e58f8bd"),
        (&[0; 83], "006a1127a8c76c6f767b79fe58e97a70cbdfc9e9"),
        (&[0; 84], "5ef468abc48fa01b791f97ff05f6196da1c0bcd8"),
        (&[0; 85], "b6ec35aa84ea388e3f915c2e35e1a58aaa884cf9"),
        (&[0; 86], "e9af6bc2e77497bac90615396b8aa732d16b8e77"),
        (&[0; 87], "ecbd6a747734781d7efb06cd1755a2a08719e625"),
        (&[0; 88], "4fcba922182b3f0721af8c2d9507620e8adcb4a5"),
        (&[0; 89], "ee34b210bbc5dc0e9899a1712ca778eb9f7d7b31"),
        (&[0; 90], "0332055466d0915c52836c094bec1edfe2ab70b2"),
        (&[0; 91], "83f9cee5a4b2a28fb56b0871f654651aa97ca642"),
        (&[0; 92], "9eacb8a6964e8f1fbd9171c468761c11355e572a"),
        (&[0; 93], "991b1df22a4192a4c4897017949a49733113fb98"),
        (&[0; 94], "169d2cd5fd18e2994de0b15dff8423531ab5781b"),
        (&[0; 95], "ddf8c2dd5fe4e9bc0ed6807d711e7547a76aef32"),
        (&[0; 96], "97bbd8bb85f86dc89e7952ac33f346fa6312238a"),
        (&[0; 97], "fc0a1b8f68fd8b297c5c141b8566c2d701bffd34"),
        (&[0; 98], "5b255f9215ff6a28abac44b3d331c4ed0202e737"),
        (&[0; 99], "1c51a032c0f7d11d116578ab08e304180e8d7de7"),
        (&[0; 100], "6464a71e78bc4ef94dec034cee243877d1617548"),
        (&[0; 101], "e98768aed93ed31596b1ef264db94dcce2e255f1"),
        (&[0; 102], "43f6f9646c3eef41f7bf0071a252a443fde8e552"),
        (&[0; 103], "971567a3f44ed6af8eca84798ca82b56bbcb628d"),
        (&[0; 104], "7b01999ddcd24e2a2feac816dd9ce6ccfd3297ff"),
        (&[0; 105], "3736d0c3f8cf9ea485ab11a38ae0701d14cc6740"),
        (&[0; 106], "e109e9180fe443bfbb3bd78a3f2855a0eac9d395"),
        (&[0; 107], "5c2aa274333415862966dcc5a342950799a610f2"),
        (&[0; 108], "791a9e2be46545c2c6d9b89d87e3c890f542fa8d"),
        (&[0; 109], "fe16e006a5d8988edd128690a4a18a69bfa0ca2a"),
        (&[0; 110], "6c6bb84e588345e4b81ced8391a96a61f7e31522"),
        (&[0; 111], "cb1635e219afd95e5efe8b533fa23e585c2f826a"),
        (&[0; 112], "1b18911b3ed54287bbc0c08d6581a5a65e50e93b"),
        (&[0; 113], "353fd7427a2015d0a0dc03b2e5a556f310751839"),
        (&[0; 114], "71424471ad81153b2aa57509bbd0eca0b6dd6657"),
        (&[0; 115], "9fde88f595fc0779d10ee8efbbc5ff193b014406"),
        (&[0; 116], "02d734b3dad956bfb07f421ebf4c22d0d9adc91e"),
        (&[0; 117], "a882de167c5725ffdc1a9c5837d667249f612bde"),
        (&[0; 118], "9693eccf8111b034753f1dea618e30df45d516a5"),
        (&[0; 119], "edb17e529e0b6bb6aa17ebc38cf863af5dfc6e96"),
        (&[0; 120], "1ac0110574dbebb731165fd306f7c5d4ba689f43"),
        (&[0; 121], "227243d1fa0bc9b6c946bd13a837a3ed0363ba7a"),
        (&[0; 122], "130627dec7a8417de360b60d71712dc3463a8736"),
        (&[0; 123], "ae49aa89bbeb90a446d803d00f4b4fdd50b59395"),
        (&[0; 124], "9633446834accc5422894fdef91801dfaacf14ab"),
        (&[0; 125], "4cca4921c8c7cd794bfa467a34e5bcb33d1e6d72"),
        (&[0; 126], "74787e7c6a8ce763609f2fa1176ddeb73bcc6aef"),
        (&[0; 127], "7826e5dc51a66f9787eeb8c04059474f9cfa962b"),
    ];
    impl_test!(Sha0, official, OFFICIAL, Sha0::default());
    impl_test!(Sha0, zero_fill, ZERO_FILL, Sha0::default());
}
