// Reference
// https://keccak.team/files/Keccak-reference-3.0.pdf

// Keccak-f[b]
// b = r + c
// b ∈ {25,50,100,200,400,800,1600}
// w ∈ {1,2,4,8,16,32,64}

// SHA-3 Submission
// https://keccak.team/files/Keccak-submission-3.pdf
// Keccak-224: [r=1152, c=448]
// Keccak-256: [r=1088, c=512]
// Keccak-384: [r=832, c=768]
// Keccak-512: [r=576, c=1024]

#![no_std]
#[macro_use]
extern crate alloc;

mod consts;

mod keccak224;
mod keccak256;
mod keccak384;
mod keccak512;

use alloc::vec::Vec;
use core::convert::TryInto;
use core::{any, mem};

use consts::*;

use utils::Hash;

pub use keccak224::Keccak224;
pub use keccak256::Keccak256;
pub use keccak384::Keccak384;
pub use keccak512::Keccak512;

struct Keccak<T> {
    state: [[T; 5]; 5], // A, S
    l: usize,
    n: usize,
    r: usize, // rate
    w: usize, // lane size
}

macro_rules! impl_keccak_f {
    ($Name: ident, $Size: ident, $Bitrate: expr, $RC: expr, $R: expr) => {
        pub struct $Name(Keccak<$Size>);
        impl $Name {
            pub fn new(r: usize, c: usize, n: usize) -> Self {
                // w = b/25
                // w = 2^l => l = log2(w)
                if r < 8 {
                    panic!("r must be smaller than 8, but got {}", r);
                }
                if r % 8 != 0 {
                    panic!(
                        "r must be a multiple of 8 in this implementation, but got {}",
                        r
                    );
                }
                if (r + c) != $Bitrate {
                    panic!(
                        "bitrate must be 1600, but got {}(rate={}, capacity={})",
                        r + c,
                        r,
                        c
                    );
                }
                let l = {
                    let mut w = (r + c) / 25;
                    let mut l = 0;
                    while w > 1 {
                        w /= 2;
                        l += 1;
                    }
                    l
                };
                Self(Keccak::<$Size> {
                    state: [[0; 5]; 5],
                    l,
                    n,
                    r,
                    w: (r + c) / 25,
                })
            }
            fn round(&mut self, rc: $Size) {
                let mut b = [[0; 5]; 5];
                let mut c = [0; 5];
                let mut d = [0; 5];
                // Theta step
                for x in 0..5 {
                    c[x] = self.0.state[x][0]
                        ^ self.0.state[x][1]
                        ^ self.0.state[x][2]
                        ^ self.0.state[x][3]
                        ^ self.0.state[x][4];
                }
                for x in 0..5 {
                    // https://keccak.team/keccak_specs_summary.html
                    // 疑似コードによるとc[x-1]だが、これだとusizeの範囲外の値が発生する。
                    // 4, 0, 1, 2, 3の順に要素を見ればいいので、(x + 4) % 5。
                    d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                }
                for x in 0..5 {
                    for y in 0..5 {
                        self.0.state[x][y] ^= d[x];
                    }
                }
                // Rho and Pi step
                for x in 0..5 {
                    for y in 0..5 {
                        b[y][(2 * x + 3 * y) % 5] = self.0.state[x][y].rotate_left($R[x][y]);
                    }
                }
                // Chi step
                for x in 0..5 {
                    for y in 0..5 {
                        self.0.state[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
                    }
                }
                // Iota step
                self.0.state[0][0] ^= rc;
            }
            fn keccak_f(&mut self) {
                for i in 0..(12 + 2 * self.0.l) {
                    self.round($RC[i]);
                }
            }
            fn absorb(&mut self, pi: &[[$Size; 5]; 5]) {
                for x in 0..5 {
                    for y in 0..5 {
                        self.0.state[y][x] ^= pi[x][y];
                    }
                }
                self.keccak_f();
            }
            fn squeeze(&mut self) -> Vec<u8> {
                let lane_size = self.0.w / 8;
                let rate_size = self.0.r / 8;
                let mut z = vec![0; self.0.n];
                let mut s = [0; 8 * 5 * 5];
                let mut output_length = self.0.n * 8;
                let mut z_len = 0;
                while output_length > 0 {
                    for x in 0..5 {
                        for y in 0..5 {
                            let head = x * 5 * lane_size + y * lane_size;
                            s[head..head + lane_size]
                                .copy_from_slice(&self.0.state[y][x].to_le_bytes()[0..lane_size]);
                        }
                    }
                    if output_length > self.0.r {
                        z[z_len..z_len + rate_size].copy_from_slice(&s[..rate_size]);
                        z_len += rate_size;
                        self.keccak_f();
                        output_length -= self.0.r;
                    } else {
                        z[z_len..].copy_from_slice(&s[..output_length / 8]);
                        output_length = 0;
                    }
                }
                z[0..self.0.n].to_vec()
            }
            pub fn keccak(&mut self, message: &[u8], d: u8) -> Vec<u8> {
                let l = message.len();
                let lane_size = self.0.w / 8;
                let rate_size = self.0.r / 8;
                let mut padded_lane = [0u8; mem::size_of::<$Size>()];
                let mut padded_block = [0u8; 8 * 25];
                let mut pi: [[$Size; 5]; 5] = [[0; 5]; 5];
                if l >= rate_size {
                    message.chunks_exact(rate_size).for_each(|lanes| {
                        lanes
                            .chunks_exact(lane_size)
                            .enumerate()
                            .for_each(|(i, lane)| {
                                padded_lane[8 - lane_size..8].copy_from_slice(lane);
                                pi[i / 5][i % 5] = $Size::from_le_bytes(padded_lane);
                            });
                        self.absorb(&pi)
                    });
                } else if l == 0 {
                    padded_block[0] = d;
                    padded_block[rate_size - 1] |= 0x80;
                    (0..25).for_each(|i| {
                        pi[i / 5][i % 5] = $Size::from_le_bytes(
                            (0..mem::size_of::<$Size>())
                                .map(|j| padded_block[i * 8 + j])
                                .collect::<Vec<u8>>()
                                .try_into()
                                .unwrap_or_else(|_| {
                                    panic!(
                                        "Failed to convert Vec<{}> into [u8; {}]",
                                        any::type_name::<$Size>(),
                                        mem::size_of::<$Size>()
                                    )
                                }),
                        );
                    });
                    self.absorb(&pi)
                }
                if l != 0 {
                    let offset = (l / rate_size) * rate_size;
                    let remainder = l % rate_size;
                    let mut byte_block = [0u8; 8 * 25];
                    byte_block[..remainder].copy_from_slice(&message[offset..]);
                    byte_block[remainder] = d;
                    byte_block[rate_size - 1] |= 0x80;
                    byte_block
                        .chunks_exact(lane_size)
                        .enumerate()
                        .for_each(|(i, lane)| {
                            padded_lane[8 - lane_size..8].copy_from_slice(lane);
                            pi[i / 5][i % 5] = $Size::from_le_bytes(padded_lane);
                        });
                    self.absorb(&pi);
                }
                // Squeezing phase
                let mut output_length = self.0.n;
                while output_length > 0 {
                    if output_length > self.0.r {
                        self.keccak_f();
                        output_length -= self.0.r;
                    } else {
                        output_length = 0;
                    }
                }
                self.squeeze()
            }
        }
        impl Hash for $Name {
            fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
                self.keccak(message, 0x01)
            }
        }
    };
}

impl_keccak_f!(KeccakF1600, u64, 1600, RC1600, R1600);
impl_keccak_f!(KeccakF800, u32, 800, RC800, R800);
impl_keccak_f!(KeccakF400, u16, 400, RC400, R400);
impl_keccak_f!(KeccakF200, u8, 200, RC200, R200);

#[cfg(test)]
mod tests {
    use super::KeccakF1600;

    #[test]
    #[should_panic(expected = "r must be a multiple of 8 in this implementation, but got 570")]
    fn keccak_f_1600_r_is_not_multiple_of_8() {
        KeccakF1600::new(570, 1030, 64);
    }
    #[test]
    #[should_panic(expected = "r must be smaller than 8, but got 0")]
    fn keccak_f_1600_r_is_smaller_than_8() {
        KeccakF1600::new(0, 1025, 64);
    }
    #[test]
    #[should_panic(expected = "bitrate must be 1600, but got 1601(rate=576, capacity=1025)")]
    fn keccak_f_1600_bitrate_is_not_1600() {
        KeccakF1600::new(576, 1025, 64);
    }
}
