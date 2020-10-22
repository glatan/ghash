use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

macro_rules! init_w {
    ( $w:expr, $( $t:expr ),* ) => {
        $(
            $w[$t] = $w[$t - 3] ^ $w[$t - 8] ^ $w[$t - 14] ^ $w[$t - 16];
        )*
    };
}

macro_rules! round {
    ($t:expr, $temp:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $w:expr) => {
        $temp = $a
            .rotate_left(5)
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($e)
            .wrapping_add($w[$t])
            .wrapping_add(K[$t / 20]);
        $e = $d;
        $d = $c;
        $c = $b.rotate_left(30);
        $b = $a;
        $a = $temp;
    };
}

const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

const fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}
const fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
const fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

pub struct Sha0 {
    status: [u32; 5],
}

impl Sha0 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
    fn compress(&mut self, m: &[u32; 16]) {
        let [mut a, mut b, mut c, mut d, mut e] = self.status;
        let mut temp;

        let mut w = [0; 80];
        w[..16].copy_from_slice(m);
        init_w!(
            // Same as (16..80).for_each(|t| w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
            w, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79
        );

        // Round 1
        round!(0, temp, a, b, c, d, e, ch, w);
        round!(1, temp, a, b, c, d, e, ch, w);
        round!(2, temp, a, b, c, d, e, ch, w);
        round!(3, temp, a, b, c, d, e, ch, w);
        round!(4, temp, a, b, c, d, e, ch, w);
        round!(5, temp, a, b, c, d, e, ch, w);
        round!(6, temp, a, b, c, d, e, ch, w);
        round!(7, temp, a, b, c, d, e, ch, w);
        round!(8, temp, a, b, c, d, e, ch, w);
        round!(9, temp, a, b, c, d, e, ch, w);
        round!(10, temp, a, b, c, d, e, ch, w);
        round!(11, temp, a, b, c, d, e, ch, w);
        round!(12, temp, a, b, c, d, e, ch, w);
        round!(13, temp, a, b, c, d, e, ch, w);
        round!(14, temp, a, b, c, d, e, ch, w);
        round!(15, temp, a, b, c, d, e, ch, w);
        round!(16, temp, a, b, c, d, e, ch, w);
        round!(17, temp, a, b, c, d, e, ch, w);
        round!(18, temp, a, b, c, d, e, ch, w);
        round!(19, temp, a, b, c, d, e, ch, w);
        // Round 2
        round!(20, temp, a, b, c, d, e, parity, w);
        round!(21, temp, a, b, c, d, e, parity, w);
        round!(22, temp, a, b, c, d, e, parity, w);
        round!(23, temp, a, b, c, d, e, parity, w);
        round!(24, temp, a, b, c, d, e, parity, w);
        round!(25, temp, a, b, c, d, e, parity, w);
        round!(26, temp, a, b, c, d, e, parity, w);
        round!(27, temp, a, b, c, d, e, parity, w);
        round!(28, temp, a, b, c, d, e, parity, w);
        round!(29, temp, a, b, c, d, e, parity, w);
        round!(30, temp, a, b, c, d, e, parity, w);
        round!(31, temp, a, b, c, d, e, parity, w);
        round!(32, temp, a, b, c, d, e, parity, w);
        round!(33, temp, a, b, c, d, e, parity, w);
        round!(34, temp, a, b, c, d, e, parity, w);
        round!(35, temp, a, b, c, d, e, parity, w);
        round!(36, temp, a, b, c, d, e, parity, w);
        round!(37, temp, a, b, c, d, e, parity, w);
        round!(38, temp, a, b, c, d, e, parity, w);
        round!(39, temp, a, b, c, d, e, parity, w);
        // Round 3
        round!(40, temp, a, b, c, d, e, maj, w);
        round!(41, temp, a, b, c, d, e, maj, w);
        round!(42, temp, a, b, c, d, e, maj, w);
        round!(43, temp, a, b, c, d, e, maj, w);
        round!(44, temp, a, b, c, d, e, maj, w);
        round!(45, temp, a, b, c, d, e, maj, w);
        round!(46, temp, a, b, c, d, e, maj, w);
        round!(47, temp, a, b, c, d, e, maj, w);
        round!(48, temp, a, b, c, d, e, maj, w);
        round!(49, temp, a, b, c, d, e, maj, w);
        round!(50, temp, a, b, c, d, e, maj, w);
        round!(51, temp, a, b, c, d, e, maj, w);
        round!(52, temp, a, b, c, d, e, maj, w);
        round!(53, temp, a, b, c, d, e, maj, w);
        round!(54, temp, a, b, c, d, e, maj, w);
        round!(55, temp, a, b, c, d, e, maj, w);
        round!(56, temp, a, b, c, d, e, maj, w);
        round!(57, temp, a, b, c, d, e, maj, w);
        round!(58, temp, a, b, c, d, e, maj, w);
        round!(59, temp, a, b, c, d, e, maj, w);
        // Round 4
        round!(60, temp, a, b, c, d, e, parity, w);
        round!(61, temp, a, b, c, d, e, parity, w);
        round!(62, temp, a, b, c, d, e, parity, w);
        round!(63, temp, a, b, c, d, e, parity, w);
        round!(64, temp, a, b, c, d, e, parity, w);
        round!(65, temp, a, b, c, d, e, parity, w);
        round!(66, temp, a, b, c, d, e, parity, w);
        round!(67, temp, a, b, c, d, e, parity, w);
        round!(68, temp, a, b, c, d, e, parity, w);
        round!(69, temp, a, b, c, d, e, parity, w);
        round!(70, temp, a, b, c, d, e, parity, w);
        round!(71, temp, a, b, c, d, e, parity, w);
        round!(72, temp, a, b, c, d, e, parity, w);
        round!(73, temp, a, b, c, d, e, parity, w);
        round!(74, temp, a, b, c, d, e, parity, w);
        round!(75, temp, a, b, c, d, e, parity, w);
        round!(76, temp, a, b, c, d, e, parity, w);
        round!(77, temp, a, b, c, d, e, parity, w);
        round!(78, temp, a, b, c, d, e, parity, w);
        round!(79, temp, a, b, c, d, e, parity, w);

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
            status: [
                0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0,
            ],
        }
    }
}

impl Hash for Sha0 {
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
    use super::Sha0;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
        // https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
        // https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
        ("abc".as_bytes(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
        ),
    ];
    impl_test!(Sha0, official, OFFICIAL, Sha0::default());
}
