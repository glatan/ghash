use utils::Hash;

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
    use utils::impl_test;

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
    impl_test!(Md2, official, OFFICIAL, Md2::default());
}
