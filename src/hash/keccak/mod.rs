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

use super::Hash;
use std::cmp::Ordering;

mod keccak224;
mod keccak256;
mod keccak384;
mod keccak512;

pub use keccak224::Keccak224;
pub use keccak256::Keccak256;
pub use keccak384::Keccak384;
pub use keccak512::Keccak512;

// RC[i]
#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
    0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088,
    0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B,
    0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
    0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
    0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

// r[x,y]
#[rustfmt::skip]
const R: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

pub(crate) struct Keccak {
    lane_block: Vec<u64>,
    state: [[u64; 5]; 5], // A, S
    l: usize,
    n: usize,
    r: usize, // bitrate
    w: usize, // lane size
}

impl Keccak {
    pub fn new(r: usize, c: usize, n: usize) -> Self {
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
            lane_block: Vec::new(),
            l: (((r + c) / 25) as f32).log2() as usize,
            n,
            r,
            w: (r + c) / 25,
        }
    }
    // 1000...0001 Style
    // (self.r / 8) byteの倍数にパディングする。例: r=1152の場合は144byteの倍数
    pub(crate) fn padding(&mut self, message: &[u8], suffix: u8) {
        let mut m = message.to_vec();
        let l = message.len();
        let rate_length = self.r / 8;
        m.push(suffix);
        match (l % rate_length).cmp(&(rate_length - 1)) {
            Ordering::Greater => {
                m.append(&mut vec![0; 2 * rate_length - 1 - (l % rate_length)]);
            }
            Ordering::Less => {
                m.append(&mut vec![0; rate_length - 1 - (l % rate_length)]);
            }
            Ordering::Equal => (),
        }
        // padded message length must be a multiple of (self.r / 8)[byte]
        debug_assert_eq!((m.len() % (self.r / 8)), 0);
        let n = m.len();
        m[n - 1] |= 0x80;
        let lane_size = self.w / 8; // byte length of lane
        let rate_length = self.r / 8; // byte length of rate
        let padded_lanes = m // パディングして、64バイト(u8 x 8)になったレーン
            .chunks_exact(lane_size)
            .flat_map(|chunk| {
                let mut lane = chunk.to_vec();
                lane.reverse(); // little endianに変換
                lane.append(&mut vec![0u8; 8 - lane_size]); // pi[x][y]はu64なので0パディングを行う。
                lane
            })
            .collect::<Vec<u8>>();
        self.lane_block = {
            let mut blocks = Vec::with_capacity(m.len() / lane_size);
            // n: block index
            for n in 0..(padded_lanes.len() / rate_length) {
                // m: lane index
                for m in 0..((padded_lanes.len() / 8) / (padded_lanes.len() / rate_length)) {
                    // lane_blockはすでにlittle_endianになっているのでエンディアン変換は行わない。
                    blocks.push(u64::from_be_bytes([
                        padded_lanes[n * rate_length + m * 8],
                        padded_lanes[n * rate_length + m * 8 + 1],
                        padded_lanes[n * rate_length + m * 8 + 2],
                        padded_lanes[n * rate_length + m * 8 + 3],
                        padded_lanes[n * rate_length + m * 8 + 4],
                        padded_lanes[n * rate_length + m * 8 + 5],
                        padded_lanes[n * rate_length + m * 8 + 6],
                        padded_lanes[n * rate_length + m * 8 + 7],
                    ]));
                }
                while blocks.len() % 25 != 0 {
                    blocks.push(0);
                }
            }
            blocks
        };
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
        let n = 12 + 2 * self.l;
        for i in 0..n {
            // A: self.state
            self.state = round(self.state, RC[i]);
        }
    }
    pub(crate) fn keccak(&mut self) -> Vec<u8> {
        // Initialize (S initialized in Self::new())
        // Absorbing phase
        for n in 0..(self.lane_block.len() / 25) {
            let mut pi = [[0; 5]; 5];
            for y in 0..5 {
                for x in 0..5 {
                    pi[x][y] = self.lane_block[(x + 5 * y + n * 25)];
                }
            }
            for y in 0..5 {
                for x in 0..5 {
                    self.state[x][y] ^= pi[x][y] as u64;
                }
            }
            self.keccak_f();
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
