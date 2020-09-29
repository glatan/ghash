use super::Hash;
use crate::impl_md_flow;
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

pub struct Sha1 {
    status: [u32; 5],
}

impl Sha1 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u32; 16]) {
        let (mut a, mut b, mut c, mut d, mut e);
        let mut temp;
        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
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

impl Default for Sha1 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            status: [
                0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
            ],
        }
    }
}

impl Hash for Sha1 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u32=> self, message, from_be_bytes, to_be_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 4] = [
        // https://tools.ietf.org/html/rfc3174
        ("abc".as_bytes(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        ("a".as_bytes(), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
        (
            "0123456701234567012345670123456701234567012345670123456701234567".as_bytes(),
            "e0c094e867ef46c350ef54a7f59dd60bed92ae83",
        ),
    ];
    const ZERO_FILL: [(&[u8], &str); (512 * 2) / 8] = [
        (&[0; 0], "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (&[0; 1], "5ba93c9db0cff93f52b521d7420e43f6eda2784f"),
        (&[0; 2], "1489f923c4dca729178b3e3233458550d8dddf29"),
        (&[0; 3], "29e2dcfbb16f63bb0254df7585a15bb6fb5e927d"),
        (&[0; 4], "9069ca78e7450a285173431b3e52c5c25299e473"),
        (&[0; 5], "a10909c2cdcaf5adb7e6b092a4faba558b62bd96"),
        (&[0; 6], "7722745105e9e02e8f1aaf17f7b3aac5c56cd805"),
        (&[0; 7], "77ce0377defbd11b77b1f4ad54ca40ea5ef28490"),
        (&[0; 8], "05fe405753166f125559e7c9ac558654f107c7e9"),
        (&[0; 9], "c259e771b237769cb6bce9a5ab734c576a6da3e1"),
        (&[0; 10], "9694c4ebd673a5e2fd26e4b2e64f92e914ebd95f"),
        (&[0; 11], "e89931b7aa0422594a6876f9bd77450cdb6353ec"),
        (&[0; 12], "2c513f149e737ec4063fc1d37aee9beabc4b4bbf"),
        (&[0; 13], "022f36e30159ec10fbb94087ecce83a62dce33c4"),
        (&[0; 14], "4595c5b7ac9f265cdf89acec0069630697680f96"),
        (&[0; 15], "bba04f6985f560446c122d235ed2e51bf7c10864"),
        (&[0; 16], "e129f27c5103bc5cc44bcdf0a15e160d445066ff"),
        (&[0; 17], "ed24e12820f2f900ae383b7cc4f2b31c402db1be"),
        (&[0; 18], "a770e927c71c77a0a9ba32e12cd7eae07148f0e7"),
        (&[0; 19], "61a27566df0bd1c1db790bb1108f7cb3b4b7213d"),
        (&[0; 20], "6768033e216468247bd031a0a2d9876d79818f8f"),
        (&[0; 21], "3082a2f97b22b4602e8d39083eef2ca0f7e54c4c"),
        (&[0; 22], "60ab0dd2ef31cfb96d52fa0a429c3803417db5c2"),
        (&[0; 23], "b92291c98ccdff52da0ca035f2086e45f64985b9"),
        (&[0; 24], "d3399b7262fb56cb9ed053d68db9291c410839c4"),
        (&[0; 25], "3b575420ceea4203152041be00dc80519d1532b5"),
        (&[0; 26], "0db2a00e53ccf8ef330179835091f6b070c1ef52"),
        (&[0; 27], "b8b17ad613463c3c9a1fe928819fb30cb853e6b1"),
        (&[0; 28], "40bf0c6cf2807a6e3c7a97fbd25244690e752b26"),
        (&[0; 29], "1da89865c5192465f8f4fe62d454c2175aff4441"),
        (&[0; 30], "deb6c11e1971aa61dbbcbc76e5ea7553a5bea7b7"),
        (&[0; 31], "6a4589599cd1c477e916474e7b029e9a4e92019b"),
        (&[0; 32], "de8a847bff8c343d69b853a215e6ee775ef2ef96"),
        (&[0; 33], "01ec548baccbe69625b54206ef7100f5ed03719f"),
        (&[0; 34], "3173532552077d0d796c3628ac35c76343dc3a04"),
        (&[0; 35], "690cd5cb8923ae1a4c6dd01447fd874008cda49e"),
        (&[0; 36], "8696cf0f4655636cc93c566c1be2dad311da646c"),
        (&[0; 37], "d4c1242413f8f8dbe8d49608996b7f997a99d4da"),
        (&[0; 38], "d576c908b43ed0023cd12557d5831f20b24e42ab"),
        (&[0; 39], "6d30d645e5c5ce43c166c9ca18613a3f2f90efd0"),
        (&[0; 40], "b80de5d138758541c5f05265ad144ab9fa86d1db"),
        (&[0; 41], "669b1c85ecbafe23c999100f55a23e06bf59ead7"),
        (&[0; 42], "040e5ac904de86328cca053a15596e118fc5da24"),
        (&[0; 43], "427eada5386c430a75597deab0f2f8e76b17a5c8"),
        (&[0; 44], "045c85ba38952325e126c70962cc0f9d9077bc67"),
        (&[0; 45], "74f00432af01b4b1fcf644f3dea879bb376c1adb"),
        (&[0; 46], "e0fdc90c2ca2a0219c99d2758e68c18875a3e11e"),
        (&[0; 47], "50f3b486f99fb22648d26870e7a5cba01caed3da"),
        (&[0; 48], "c17fd92682ca5b304ac71074b558dda9e8eb4d66"),
        (&[0; 49], "6b3d33e00f5b9deae2826f80644cb4f6e78b7401"),
        (&[0; 50], "8cd537a621659c289f0707bad94719b5782ddb1f"),
        (&[0; 51], "8edb36d75f26dc46aae4520b02deea1a645cfbc3"),
        (&[0; 52], "2f1050adf64f33298ff0ce423eb86d4728441b21"),
        (&[0; 53], "d6de27e734eec57d1dda73489b4a6d6eecae3038"),
        (&[0; 54], "7aa0ee429b305a7017069c2d5d7c4839a063cfa5"),
        (&[0; 55], "8e8832c642a6a38c74c17fc92ccedc266c108e6c"),
        (&[0; 56], "9438e360f578e12c0e0e8ed28e2c125c1cefee16"),
        (&[0; 57], "0f2bf6d5e1a0209d19f8f6e7d08b3e2d9cf4c5ab"),
        (&[0; 58], "ecbffb23eb3053ead40dfc45afbb2d565afa1d03"),
        (&[0; 59], "5c7d7be28c2b70cc806f465667a798f8c5272b19"),
        (&[0; 60], "fb3d8fb74570a077e332993f7d3d27603501b987"),
        (&[0; 61], "b32c03194e03c658007c5b6bdedced39ddefc291"),
        (&[0; 62], "566538c1539e2db072bd6dd57dbaae4e470ad831"),
        (&[0; 63], "0b8bf9fc37ad802cefa6733ec62b09d5f43a1b75"),
        (&[0; 64], "c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7"),
        (&[0; 65], "f0fa45906bd0f4c3668fcd0d8f68d4b298b30e5b"),
        (&[0; 66], "707efc314ec536abed535cdb1b2414aba4713577"),
        (&[0; 67], "931613845dd0e72f1b1a5ba0c89f1c34e5cc089d"),
        (&[0; 68], "46fe3f0a75b18d406d86aca0ed37bb706ed8246b"),
        (&[0; 69], "64558cebbeaf7858a3075e993f45ea9f4573b984"),
        (&[0; 70], "3cc4a1cc99309a6512d22cf3cd62537f971893ab"),
        (&[0; 71], "ae9c81906afe9cc485d6808c62a7e2fd227ac6c6"),
        (&[0; 72], "0d0e47938f6e00166e7352732ddfb7c610f44db2"),
        (&[0; 73], "03a0093aa2d121e7ca3feabb0ec19ff2e15179b8"),
        (&[0; 74], "1dcc0c704303ccc1729abd618f490073331e8b22"),
        (&[0; 75], "646aaf623a9b65f3054571ba8680342cf02b6225"),
        (&[0; 76], "ece05370137621ead05fcf468ba546e2dab83c7a"),
        (&[0; 77], "9898d25a214dba04ebd7e3030ac9e2e90ea7a369"),
        (&[0; 78], "56615cdf87de9fbc9e4150e207f21122035e6c40"),
        (&[0; 79], "a66c2665344d288a9afcec3e1d39366654011462"),
        (&[0; 80], "8fc36a50d0ba5aabfa3cb92d81fe9fdc4686e6a3"),
        (&[0; 81], "f8ebbbe3ad6a8cfd13607fd3a7fad7a3a7a50158"),
        (&[0; 82], "20edc764a349bcac33d8d034eec1f8e933eebe01"),
        (&[0; 83], "44d23c08c887d443c149bf36b52af0a1fc01a219"),
        (&[0; 84], "f68f30ee52133e400606a6be91d2d982388b43a2"),
        (&[0; 85], "def5026103297fa44a2185104f2ee400cb93329c"),
        (&[0; 86], "6798e187e97f92a05cd826ea8d8666030424e977"),
        (&[0; 87], "ae709bc0b70be49e51eb8912c0a1cca9e6c80872"),
        (&[0; 88], "5c0a9085206c2dafcf9c1cb2c0a8dabdc387c895"),
        (&[0; 89], "111ffd83edcb095d251067456a3a60b754b4c717"),
        (&[0; 90], "bc243136d6d9e400e493af133fed7a0c3004874c"),
        (&[0; 91], "3355b6761da0494a9c736fd492ffb13bcbbc83de"),
        (&[0; 92], "836f19cb3de11d49cf00781f211e535fb9dba1f3"),
        (&[0; 93], "c264d31acdf5c68a97ba444c7fd7e8af853122c4"),
        (&[0; 94], "ea7d2164761f6945601634e6a9bc53d1809faef1"),
        (&[0; 95], "bd057d7f49143824e45263147a02a580137fabef"),
        (&[0; 96], "c49a9785b2243f2f080daad1747f119acceccfa5"),
        (&[0; 97], "fa205d2a65684c6245a2272facf45fb12ace4014"),
        (&[0; 98], "a568e30784b1df87b30e1d4a2234de7b706b3d27"),
        (&[0; 99], "d991c16949bd5e85e768385440e18d493ce3aa46"),
        (&[0; 100], "ed4a77d1b56a118938788fc53037759b6c501e3d"),
        (&[0; 101], "93436ea60c5dcdd2e9893a025f560ab72422ae8c"),
        (&[0; 102], "be8307123a0e9ed7c251fe451049c60cbb108244"),
        (&[0; 103], "558ae348a40d50bb93d89fa2f25483d0afed1d32"),
        (&[0; 104], "0b325041dc182abbe3ddc9f833d781a4543b0a6d"),
        (&[0; 105], "ae9fb8e72137c1729ffb559aa5f541bff78661c9"),
        (&[0; 106], "3ac8e44a9491c16bcd86dab6781acc4f7e1f76a7"),
        (&[0; 107], "51eba728560c4477f64974d5d726b3391a2f6c62"),
        (&[0; 108], "1d58c87e67c4b9d2c7ddd6b1f9c033eff16ca9b8"),
        (&[0; 109], "9182a487b67f837de1ada4c11e3c4d567a554986"),
        (&[0; 110], "b856abf03c3dd98afecd55186536ceaf03b9c7ab"),
        (&[0; 111], "dd90903d2f566a3922979dd5e18378a075c7ed33"),
        (&[0; 112], "5c0168621a045c606b075a182ad39370e6343683"),
        (&[0; 113], "f16acd929b52b77b7dad02dbceff25992f4ba95e"),
        (&[0; 114], "f7430efc590e79b847ab97b6e429cd07ef886726"),
        (&[0; 115], "5b406536b32ad45deb8219f80cabb02d88a1b91c"),
        (&[0; 116], "67236ce557839585f058ac318e51be7bc0f745e2"),
        (&[0; 117], "58249dba429c6b997b3849d5b3a33b7c139b1e1f"),
        (&[0; 118], "13ac7900e24c5183b00479e52a43dc11663bbacf"),
        (&[0; 119], "85634f17f58bda0e4f0515dfb68bc1af922a031f"),
        (&[0; 120], "b110a88a11436b215220486c1081dec2fb0f389a"),
        (&[0; 121], "8e6d9001ca20e76482e1ab88d54d47c65c8c7836"),
        (&[0; 122], "d53e4c5562cafbb535c477e05223688b0d5faacd"),
        (&[0; 123], "3d9a8dc570e665c0330ebedd932d7ef813bddfa4"),
        (&[0; 124], "2ccf78e3b22f294c2b9d2af73d2fede8af96d6a8"),
        (&[0; 125], "80691ad30930c04fe1bb2f645f9c6c0548ece80d"),
        (&[0; 126], "339820e6c5f6ba11a584e7c37c936e3778147a0a"),
        (&[0; 127], "6053d761084e9eb4ec12810110de07e7320787b6"),
    ];
    impl_test!(Sha1, official, OFFICIAL, Sha1::default());
    impl_test!(Sha1, zero_fill, ZERO_FILL, Sha1::default());
}
