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

mod keccak224;
mod keccak256;
mod keccak384;
mod keccak512;

pub use utils::Hash;

pub use keccak224::Keccak224;
pub use keccak256::Keccak256;
pub use keccak384::Keccak384;
pub use keccak512::Keccak512;

mod consts;

use crate::consts::*;

pub struct Keccak {
    state: [[u64; 5]; 5], // A, S
    l: usize,
    n: usize,
    r: usize, // bitrate
    w: usize, // lane size
}

impl Keccak {
    fn new(r: usize, c: usize, n: usize) -> Self {
        // w = b/25
        // w = 2^l => l = log2(w)
        if r % 8 != 0 {
            panic!(
                "r must be a multiple of 8 in this implementation, but got {}",
                r
            );
        }
        if n % 8 != 0 {
            panic!("output length must be a multiple of 8, but got {}", n);
        }
        if ![25, 50, 100, 200, 400, 800, 1600].contains(&(r + c)) {
            panic!("bitrate must be in [25, 50, 100, 200, 400, 800, 1600], but got {}(rate={}, capacity={})", r + c, r, c);
        }
        Self {
            state: [[0; 5]; 5],
            l: (((r + c) / 25) as f32).log2() as usize,
            n,
            r,
            w: (r + c) / 25,
        }
    }
    fn keccak_f(&mut self) {
        fn round(mut a: [[u64; 5]; 5], rc: u64) -> [[u64; 5]; 5] {
            let mut b = [[0; 5]; 5];
            let mut c = [0; 5];
            let mut d = [0; 5];
            // Theta step
            for x in 0..5 {
                c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
            }
            for x in 0..5 {
                // https://keccak.team/keccak_specs_summary.html
                // 疑似コードによるとc[x-1]だが、これだとusizeの範囲外の値が発生する。
                // 4, 0, 1, 2, 3の順に要素を見ればいいので、(x + 4) % 5。
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    a[x][y] ^= d[x];
                }
            }
            // Rho and Pi step
            for x in 0..5 {
                for y in 0..5 {
                    b[y][(2 * x + 3 * y) % 5] = a[x][y].rotate_left(R[x][y]);
                }
            }
            // Chi step
            for x in 0..5 {
                for y in 0..5 {
                    a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
                }
            }
            // Iota step
            a[0][0] ^= rc;
            // Return A
            a
        }
        for i in 0..(12 + 2 * self.l) {
            // A: self.state
            self.state = round(self.state, RC[i]);
        }
    }
    fn absorb(&mut self, pi: &[[u64; 5]; 5]) {
        for x in 0..5 {
            for y in 0..5 {
                self.state[y][x] ^= pi[x][y];
            }
        }
        self.keccak_f();
    }
    pub fn keccak(&mut self, message: &[u8], d: u8) -> Vec<u8> {
        let l = message.len();
        let lane_size = self.w / 8;
        let rate_size = self.r / 8;
        let mut padded_lane = [0u8; 8];
        let mut padded_block = [0u8; 8 * 25];
        let mut pi = [[0u64; 5]; 5];
        if l >= rate_size {
            message.chunks_exact(rate_size).for_each(|lanes| {
                lanes
                    .chunks_exact(lane_size)
                    .enumerate()
                    .for_each(|(i, lane)| {
                        padded_lane[8 - lane_size..8].copy_from_slice(lane);
                        pi[i / 5][i % 5] = u64::from_le_bytes(padded_lane);
                    });
                self.absorb(&pi)
            });
        } else if l == 0 {
            padded_block[0] = d;
            padded_block[rate_size - 1] |= 0x80;
            (0..25).for_each(|i| {
                pi[i / 5][i % 5] = u64::from_le_bytes([
                    padded_block[i * 8],
                    padded_block[i * 8 + 1],
                    padded_block[i * 8 + 2],
                    padded_block[i * 8 + 3],
                    padded_block[i * 8 + 4],
                    padded_block[i * 8 + 5],
                    padded_block[i * 8 + 6],
                    padded_block[i * 8 + 7],
                ]);
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
                    pi[i / 5][i % 5] = u64::from_le_bytes(padded_lane);
                });
            self.absorb(&pi);
        }
        // Squeezing phase
        let mut z = Vec::new();
        let mut output_length = self.n;
        while output_length > 0 {
            for x in 0..5 {
                for y in 0..5 {
                    z.append(&mut self.state[y][x].to_le_bytes().to_vec());
                }
            }
            if output_length > self.r {
                self.keccak_f();
                output_length -= self.r;
            } else {
                output_length = 0;
            }
        }
        z[0..self.n / 8].to_vec()
    }
}
