#![no_std]
extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod macros;

mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512trunc224;
mod sha512trunc256;

use core::cmp::Ordering;

use crate::consts::{
    big_sigma32_0, big_sigma32_1, big_sigma64_0, big_sigma64_1, ch32, ch64, maj32, maj64,
    small_sigma32_0, small_sigma32_1, small_sigma64_0, small_sigma64_1, H224, H256, H384, H512,
    H512_TRUNC224, H512_TRUNC256, K32, K64,
};

pub use sha224::Sha224;
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use sha512trunc224::Sha512Trunc224;
pub use sha512trunc256::Sha512Trunc256;
pub use utils::Hash;

#[cfg(not(feature = "minimal"))]
use utils::impl_md_flow;
#[cfg(feature = "minimal")]
use utils::impl_md_flow_minimal as impl_md_flow;

// Sha2<u32>: SHA-224 and SHA-256
// Sha2<u64>: SHA-384, SHA-512, SHA-512/224 and SHA-512/256
struct Sha2<T> {
    status: [T; 8],
}

impl Sha2<u32> {
    fn new(iv: [u32; 8]) -> Self {
        Self { status: iv }
    }
    #[cfg(not(feature = "minimal"))]
    #[allow(clippy::many_single_char_names)]
    fn compress(&mut self, m: &[u32; 16]) {
        // Initialize the eight working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        let (mut temp_1, mut temp_2);
        // Prepare the message schedule
        let mut w = [0; 64];
        w[..16].copy_from_slice(m);
        init_w32!(
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63
        );
        // Round
        round_32!(
            temp_1, temp_2, a, b, c, d, e, f, g, h, w, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63
        );
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
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    #[cfg(feature = "minimal")]
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
    fn sha2(&mut self, message: &[u8]) {
        impl_md_flow!(u32=> self, message, from_be_bytes, to_be_bytes);
    }
}

impl Sha2<u64> {
    fn new(iv: [u64; 8]) -> Self {
        Self { status: iv }
    }
    #[cfg(not(feature = "minimal"))]
    #[allow(clippy::many_single_char_names)]
    fn compress(&mut self, m: &[u64; 16]) {
        // Initialize the eight working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.status;
        let (mut temp_1, mut temp_2);
        // Prepare the message schedule
        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        init_w64!(
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 77, 78, 79
        );
        // Round
        round_64!(
            temp_1, temp_2, a, b, c, d, e, f, g, h, w, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
            79
        );
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
    #[cfg(feature = "minimal")]
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
    fn sha2(&mut self, message: &[u8]) {
        impl_md_flow!(u64=> self, message, from_be_bytes, to_be_bytes);
    }
}
