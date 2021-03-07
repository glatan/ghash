use alloc::vec::Vec;

use super::Keccak;
use crate::consts::*;

pub struct KeccakF1600(Keccak<u64>);

impl KeccakF1600 {
    pub fn new(r: usize, c: usize, n: usize) -> Self {
        // w = b/25
        // w = 2^l => l = log2(w)
        if r % 8 != 0 {
            panic!(
                "r must be a multiple of 8 in this implementation, but got {}",
                r
            );
        }
        if (r + c) != 1600 {
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
        Self(Keccak::<u64> {
            state: [[0; 5]; 5],
            l,
            n,
            r,
            w: (r + c) / 25,
        })
    }
    fn round(&mut self, rc: u64) {
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
                b[y][(2 * x + 3 * y) % 5] = self.0.state[x][y].rotate_left(R[x][y]);
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
            self.round(RC[i]);
        }
    }
    fn absorb(&mut self, pi: &[[u64; 5]; 5]) {
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
        let mut output_length = self.0.n;
        while output_length > 0 {
            for x in 0..5 {
                for y in 0..5 {
                    z.append(&mut self.0.state[y][x].to_le_bytes().to_vec());
                }
            }
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
