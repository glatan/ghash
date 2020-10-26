mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512trunc224;
mod sha512trunc256;

pub use sha224::Sha224;
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use sha512trunc224::Sha512Trunc224;
pub use sha512trunc256::Sha512Trunc256;

use crate::consts::*;

// Sha2<u32>: SHA-224 and SHA-256
// Sha2<u64>: SHA-384, SHA-512, SHA-512/224 and SHA-512/256
struct Sha2<T> {
    status: [T; 8],
}

impl Sha2<u32> {
    fn new(iv: [u32; 8]) -> Self {
        Self { status: iv }
    }
    #[inline(always)]
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u32; 16]) {
        let (mut temp_1, mut temp_2);
        // Initialize the eight working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        // Prepare the message schedule
        let mut w = [0; 64];
        w[..16].copy_from_slice(m);
        for t in 16..64 {
            w[t] = small_sigma32_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma32_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }
        // Round
        for t in 0..64 {
            temp_1 = h
                .wrapping_add(big_sigma32_1(e))
                .wrapping_add(ch32(e, f, g))
                .wrapping_add(K32[t])
                .wrapping_add(w[t]);
            temp_2 = big_sigma32_0(a).wrapping_add(maj32(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_1);
            d = c;
            c = b;
            b = a;
            a = temp_1.wrapping_add(temp_2);
        }
        // Compute the intermediate hash value
        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
        self.status[4] = self.status[4].wrapping_add(e);
        self.status[5] = self.status[5].wrapping_add(f);
        self.status[6] = self.status[6].wrapping_add(g);
        self.status[7] = self.status[7].wrapping_add(h);
    }
}

impl Sha2<u64> {
    fn new(iv: [u64; 8]) -> Self {
        Self { status: iv }
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u64; 16]) {
        let (mut temp_1, mut temp_2);
        // Initialize the eight working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        // Prepare the message schedule
        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        for t in 16..80 {
            w[t] = small_sigma64_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma64_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }
        // Round
        for t in 0..80 {
            temp_1 = h
                .wrapping_add(big_sigma64_1(e))
                .wrapping_add(ch64(e, f, g))
                .wrapping_add(K64[t])
                .wrapping_add(w[t]);
            temp_2 = big_sigma64_0(a).wrapping_add(maj64(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_1);
            d = c;
            c = b;
            b = a;
            a = temp_1.wrapping_add(temp_2);
        }
        // Compute the intermediate hash value
        self.status[0] = self.status[0].wrapping_add(a);
        self.status[1] = self.status[1].wrapping_add(b);
        self.status[2] = self.status[2].wrapping_add(c);
        self.status[3] = self.status[3].wrapping_add(d);
        self.status[4] = self.status[4].wrapping_add(e);
        self.status[5] = self.status[5].wrapping_add(f);
        self.status[6] = self.status[6].wrapping_add(g);
        self.status[7] = self.status[7].wrapping_add(h);
    }
}
