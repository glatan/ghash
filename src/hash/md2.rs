use super::Hash;

const STABLE: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
];

pub struct Md2 {
    state: [u8; 48],
}

impl Md2 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8]) {
        self.state[16..32].copy_from_slice(block);
        for i in 0..16 {
            self.state[i + 32] = block[i] ^ self.state[i];
        }
        let mut t = 0;
        for i in 0..18 {
            for k in 0..48 {
                self.state[k] ^= STABLE[t as usize];
                t = self.state[k] as usize;
            }
            t = (t + i) % 256;
        }
    }
    fn compress_checksum(&mut self, message: &[u8], padded_block: &[u8; 16]) {
        let mut checksum = [0u8; 16];
        let mut c;
        let mut l = 0;
        for i in 0..(message.len() / 16) {
            for j in 0..16 {
                c = message[16 * i + j];
                checksum[j] ^= STABLE[(c ^ l) as usize];
                l = checksum[j];
            }
        }
        for i in 0..16 {
            c = padded_block[i];
            checksum[i] ^= STABLE[(c ^ l) as usize];
            l = checksum[i];
        }
        self.compress(&checksum);
    }
}

impl Default for Md2 {
    fn default() -> Self {
        Self { state: [0; 48] }
    }
}

impl Hash for Md2 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        let len = message.len();
        if len == 0 {
            // First block is filled with 16 (padding bytes)
            self.compress(&[16; 16]);
            self.compress_checksum(&[], &[16; 16]);
        } else if len >= 16 {
            message
                .chunks_exact(16)
                .for_each(|block| self.compress(block));
        }
        if len != 0 {
            let paddlen = len % 16;
            let mut block = [(16 - paddlen) as u8; 16]; // padding
            let offset = len - paddlen;
            block[..paddlen].clone_from_slice(&message[offset..len]);
            self.compress(&block);
            self.compress_checksum(message, &block);
        }
        self.state.iter().take(16).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Md2;
    use crate::impl_test;

    const OFFICIAL: [(&[u8], &str); 6] = [
        // https://tools.ietf.org/html/rfc1319
        ("".as_bytes(), "8350e5a3e24c153df2275c9f80692773"),
        ("a".as_bytes(), "32ec01ec4a6dac72c0ab96fb34c0b5d1"),
        (
            "message digest".as_bytes(),
            "ab4f496bfb2a530b219ff33031fe06b0",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "4e8ddff3650292ab5a4108c3aa47940b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "da33def2a42df13975352846c30338cd",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "d5976f79d83d3a0dc9806c3c66f3efd8",
        ),
    ];
    const ZERO_FILL: [(&[u8], &str); (128 * 2) / 8] = [
        (&[0; 0], "8350e5a3e24c153df2275c9f80692773"),
        (&[0; 1], "ee8dbae3bc62bdc94ea63f69c1bc26c9"),
        (&[0; 2], "070e302f491955b59d83829950299cef"),
        (&[0; 3], "d0f0946bb28387b056a70ec7e8b67edb"),
        (&[0; 4], "6900c99876ed7fe0d9a24e0aad46d650"),
        (&[0; 5], "f4b1bcd96256e2dc14bb08fdf60fb975"),
        (&[0; 6], "fa4cc98e8b10311a8e247dfa5a04efdd"),
        (&[0; 7], "8238d5b245bbc922e0af675f0e00440a"),
        (&[0; 8], "a51716bb183463097d2a19c217948eea"),
        (&[0; 9], "e9463640ab97ae87eb28d0b041a34277"),
        (&[0; 10], "703cda95929b15fdb5c654e6219aa49f"),
        (&[0; 11], "d3cf4026af16641a1941902d27f096dd"),
        (&[0; 12], "9df62f2a5fe25412c068e0e0e39e903e"),
        (&[0; 13], "debc487ae3768928f10cf8fa8b13c05c"),
        (&[0; 14], "032419c77e059366282f161eeedc6dec"),
        (&[0; 15], "b20662902185c1c77c964bb7d8fb2279"),
        (&[0; 16], "3e32fe6c199520c0ca4f0e8c28ef2786"),
        (&[0; 17], "911d898992e34e10326ff9fc42be4dfe"),
        (&[0; 18], "ed14013cd2c469d43fad41914a687780"),
        (&[0; 19], "d2d450c4f0a957e5dc6d6b1a2eace20b"),
        (&[0; 20], "b67c06d2afb4f6b6acdc7850440255db"),
        (&[0; 21], "99e1a24c47fc8dadb534433e6f143abf"),
        (&[0; 22], "2e171c98e7b0aa589ee9cd541da73a1a"),
        (&[0; 23], "c1fa6efe7454af130a107415384eed41"),
        (&[0; 24], "c156f03a002d73793f98a04ad4b128b6"),
        (&[0; 25], "51b3ca7c9e62f13db8a348fa33466d95"),
        (&[0; 26], "334e7a34acd80e68fcd9cb04b1fd04de"),
        (&[0; 27], "010f498bec8942fc2075f7b36ecd896f"),
        (&[0; 28], "673c8154edaf378f9a12fbeb0077a048"),
        (&[0; 29], "57eca6b409c3ec181f86f180c8872507"),
        (&[0; 30], "61332466af5b0922b09ad9cea0c13378"),
        (&[0; 31], "9b0543471a177fc4947902d5f4912a44"),
    ];
    impl_test!(Md2, official, OFFICIAL, Md2::default());
    impl_test!(Md2, zero_fill, ZERO_FILL, Md2::default());
}
