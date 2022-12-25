g use alloc::vec::Vec;
use core::cmp::Ordering;

use utils::{impl_md_flow_minimal, Hash};

use crate::consts::{ch, maj, parity, IV, K};

pub struct Sha0 {
    status: [u32; 5],
}

impl Sha0 {
    pub fn new() -> Self {
        Self::default()
    }
    #[inline(always)]
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d, mut e] = self.status;
        let mut temp;

        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        (16..80).for_each(|t| w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);

        // Round 1
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
        // Round 2
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
        // Round 3
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
        // Round 4
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

impl Default for Sha0 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self {
            status: IV,
        }
    }
}

impl Hash for Sha0 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow_minimal!(u32=> self, message, from_be_bytes, to_be_bytes);
        self.status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}
