use super::Hash;

mod blake2b;
mod blake2s;

pub use blake2b::Blake2b;
pub use blake2s::Blake2s;

#[rustfmt::skip]
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[rustfmt::skip]
const IV32: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
];
#[rustfmt::skip]
const IV64: [u64; 8] = [
    0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179
];

const fn init_params32(n: usize, k: usize, salt: [u32; 2]) -> [u32; 8] {
    return [
        ((1 << 24) | (1 << 16) | (k << 8) | n) as u32,
        0,               // leaf length
        0,               // node offset
        0,               // node offset(count.), node depth, inner length
        salt[0].to_le(), // salt
        salt[1].to_le(), // salt
        0,               // personalization
        0,               // personalization
    ];
}

const fn init_params64(n: usize, k: usize, salt: [u64; 2]) -> [u64; 8] {
    return [
        ((1 << 24) | (1 << 16) | (k << 8) | n) as u64 | // digest length, key length, fanout, depth
        0, // leaf length
        0, // node offset
        0 |               // node depth, inner length, RFU
        0, // RFU
        0, // RFU
        salt[0].to_le(), // salt
        salt[1].to_le(), // salt
        0, // personalization
        0, // personalization
    ];
}

// Blake<u32>: BLAKE2s
// Blake<u64>: BLAKE2b
struct Blake2<T> {
    word_block: Vec<T>,
    f: bool,  // finalization flag
    l: usize, // 未処理のバイト数
    h: [T; 8],
    // p: [T; 8], // parameters
    t: [T; 2],  // counter: 処理したバイト数(と次に処理をするブロックのバイト数?)
    n: usize,   // 出力バイト数
    v: [T; 16], // state
}

// Blake2s
impl Blake2<u32> {
    pub fn new(n: usize, k: usize, salt: [u32; 2]) -> Self {
        if n < 1 || n > 32 {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        let p = init_params32(n, k, salt);
        Self {
            word_block: Vec::with_capacity(16),
            f: false,
            l: 0,
            h: [
                IV32[0] ^ p[0],
                IV32[1] ^ p[1],
                IV32[2] ^ p[2],
                IV32[3] ^ p[3],
                IV32[4] ^ p[4],
                IV32[5] ^ p[5],
                IV32[6] ^ p[6],
                IV32[7] ^ p[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    fn padding(&mut self, message: &[u8]) {
        let mut m = message.to_vec();
        self.l = message.len();
        if self.l == 0 {
            m.append(&mut vec![0; 64]);
        }
        if (self.l % 64) != 0 {
            m.append(&mut vec![0; 64 - self.l % 64]);
        }
        // create 32 bit-words from input bytes
        for i in (0..m.len()).filter(|i| i % 4 == 0) {
            self.word_block
                .push(u32::from_le_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]));
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, n: usize, i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // n: block index
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(self.word_block[SIGMA[r][2 * i] + 16 * n]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(self.word_block[SIGMA[r][2 * i + 1] + 16 * n]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }
    fn compress(&mut self) {
        // Compress blocks(1 block == 16 words, 1 word == 32 bit)
        // Compress 1 block in 1 loop
        for n in 0..(self.word_block.len() / 16) {
            // update counter
            if self.l > 64 {
                self.t[0] += 64;
                self.l -= 64;
            } else {
                self.t[0] += self.l as u32;
                self.l = 0;
                self.f = true;
            }
            // initialize state
            self.v[0] = self.h[0];
            self.v[1] = self.h[1];
            self.v[2] = self.h[2];
            self.v[3] = self.h[3];
            self.v[4] = self.h[4];
            self.v[5] = self.h[5];
            self.v[6] = self.h[6];
            self.v[7] = self.h[7];
            self.v[8] = IV32[0];
            self.v[9] = IV32[1];
            self.v[10] = IV32[2];
            self.v[11] = IV32[3];
            self.v[12] = IV32[4] ^ self.t[0];
            self.v[13] = IV32[5] ^ self.t[1];
            if self.f {
                self.v[14] = IV32[6] ^ u32::MAX;
                self.v[15] = IV32[7] ^ u32::MIN;
            } else {
                self.v[14] = IV32[6];
                self.v[15] = IV32[7];
            }
            // round
            for r in 0..10 {
                // print!("Round[{:}]: ", r);
                // for i in 0..16 {
                //     print!("{:08x}", self.v[i]);
                // }
                // println!();
                self.g(n, 0, r, 0, 4, 8, 12);
                self.g(n, 1, r, 1, 5, 9, 13);
                self.g(n, 2, r, 2, 6, 10, 14);
                self.g(n, 3, r, 3, 7, 11, 15);
                self.g(n, 4, r, 0, 5, 10, 15);
                self.g(n, 5, r, 1, 6, 11, 12);
                self.g(n, 6, r, 2, 7, 8, 13);
                self.g(n, 7, r, 3, 4, 9, 14);
            }
            // print!("Round[{:}]: ", 10);
            // for i in 0..16 {
            //     print!("{:08x}", self.v[i]);
            // }
            // println!();
            // finalize
            for i in 0..8 {
                self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
            }
        }
    }
}

impl Default for Blake2<u32> {
    fn default() -> Self {
        let p = init_params32(32, 0, [0; 2]);
        // for i in p.iter() {
        //     print!("{:08x} ", i);
        // }
        // println!();
        Self {
            word_block: Vec::with_capacity(16),
            f: false,
            l: 0,
            h: [
                IV32[0] ^ p[0],
                IV32[1] ^ p[1],
                IV32[2] ^ p[2],
                IV32[3] ^ p[3],
                IV32[4] ^ p[4],
                IV32[5] ^ p[5],
                IV32[6] ^ p[6],
                IV32[7] ^ p[7],
            ],
            t: [0; 2],
            n: 32,
            v: [0; 16],
        }
    }
}

// Blake2b
impl Blake2<u64> {
    fn new(n: usize, k: usize, salt: [u64; 2]) -> Self {
        if n < 1 || n > 64 {
            panic!("{} is not a valid number. n must be between 1 and 32.", n);
        }
        let p = init_params64(n, k, salt);
        Self {
            word_block: Vec::with_capacity(16),
            f: false,
            l: 0,
            h: [
                IV64[0] ^ p[0],
                IV64[1] ^ p[1],
                IV64[2] ^ p[2],
                IV64[3] ^ p[3],
                IV64[4] ^ p[4],
                IV64[5] ^ p[5],
                IV64[6] ^ p[6],
                IV64[7] ^ p[7],
            ],
            t: [0; 2],
            n,
            v: [0; 16],
        }
    }
    fn padding(&mut self, message: &[u8]) {
        let mut m = message.to_vec();
        self.l = message.len();
        if self.l == 0 {
            m.append(&mut vec![0; 128]);
        }
        if (self.l % 128) != 0 {
            m.append(&mut vec![0; 128 - self.l % 128]);
        }
        // create 64 bit-words from input bytes(and appending bytes)
        for i in (0..m.len()).filter(|i| i % 8 == 0) {
            self.word_block.push(u64::from_le_bytes([
                m[i],
                m[i + 1],
                m[i + 2],
                m[i + 3],
                m[i + 4],
                m[i + 5],
                m[i + 6],
                m[i + 7],
            ]));
        }
    }
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    fn g(&mut self, n: usize, i: usize, r: usize, a: usize, b: usize, c: usize, d: usize) {
        // a,b,c,d: index of self.v
        // n: block index
        // i: number of function G
        // r: round count
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(self.word_block[SIGMA[r % 10][2 * i] + 16 * n]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(32);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(24);
        self.v[a] = self.v[a]
            .wrapping_add(self.v[b])
            .wrapping_add(self.word_block[SIGMA[r % 10][2 * i + 1] + 16 * n]);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(63);
    }
    fn compress(&mut self) {
        // Compress blocks(1 block == 16 words, 1 word == 64 bit)
        // Compress 1 block in 1 loop
        for n in 0..(self.word_block.len() / 16) {
            // update counter
            if self.l > 128 {
                self.t[0] += 128;
                self.l -= 128;
            } else {
                self.t[0] += self.l as u64;
                self.l = 0;
                self.f = true;
            }
            // initialize state
            self.v[0] = self.h[0];
            self.v[1] = self.h[1];
            self.v[2] = self.h[2];
            self.v[3] = self.h[3];
            self.v[4] = self.h[4];
            self.v[5] = self.h[5];
            self.v[6] = self.h[6];
            self.v[7] = self.h[7];
            self.v[8] = IV64[0];
            self.v[9] = IV64[1];
            self.v[10] = IV64[2];
            self.v[11] = IV64[3];
            self.v[12] = IV64[4] ^ self.t[0];
            self.v[13] = IV64[5] ^ self.t[1];
            if self.f {
                self.v[14] = IV64[6] ^ u64::MAX;
                self.v[15] = IV64[7] ^ u64::MIN;
            } else {
                self.v[14] = IV64[6];
                self.v[15] = IV64[7];
            }
            // round
            for r in 0..12 {
                // print!("Round[{:}]: ", r);
                // for i in 0..16 {
                //     print!("{:08x}", self.v[i]);
                // }
                // println!();
                self.g(n, 0, r, 0, 4, 8, 12);
                self.g(n, 1, r, 1, 5, 9, 13);
                self.g(n, 2, r, 2, 6, 10, 14);
                self.g(n, 3, r, 3, 7, 11, 15);
                self.g(n, 4, r, 0, 5, 10, 15);
                self.g(n, 5, r, 1, 6, 11, 12);
                self.g(n, 6, r, 2, 7, 8, 13);
                self.g(n, 7, r, 3, 4, 9, 14);
            }
            // print!("Round[{:}]: ", 12);
            // for i in 0..16 {
            //     print!("{:08x}", self.v[i]);
            // }
            // println!();
            // finalize
            for i in 0..8 {
                self.h[i] = self.h[i] ^ self.v[i] ^ self.v[i + 8];
            }
        }
    }
}

impl Default for Blake2<u64> {
    fn default() -> Self {
        let p = init_params64(64, 0, [0; 2]);
        // for i in p.iter() {
        //     print!("{:016x} ", i);
        // }
        // println!();
        Self {
            word_block: Vec::with_capacity(16),
            f: false,
            l: 0,
            h: [
                IV64[0] ^ p[0],
                IV64[1] ^ p[1],
                IV64[2] ^ p[2],
                IV64[3] ^ p[3],
                IV64[4] ^ p[4],
                IV64[5] ^ p[5],
                IV64[6] ^ p[6],
                IV64[7] ^ p[7],
            ],
            t: [0; 2],
            n: 64,
            v: [0; 16],
        }
    }
}
