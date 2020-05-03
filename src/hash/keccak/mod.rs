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

use super::{Hash, Message};
use crate::impl_message;
use std::cmp::Ordering;
use std::mem;

mod keccak224;

pub use keccak224::Keccak224;

// RC[i]
#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_8000_808B,
    0x0000_0000_0000_8082, 0x8000_0000_0000_008B,
    0x8000_0000_0000_808A, 0x8000_0000_0000_8089,
    0x8000_0000_8000_8000, 0x8000_0000_0000_8003,
    0x0000_0000_0000_808B, 0x8000_0000_0000_8002,
    0x0000_0000_8000_0001, 0x8000_0000_0000_0080,
    0x8000_0000_8000_8081, 0x0000_0000_0000_800A,
    0x8000_0000_0000_8009, 0x8000_0000_8000_000A,
    0x0000_0000_0000_008A, 0x8000_0000_8000_8081,
    0x0000_0000_0000_0088, 0x8000_0000_0000_8080,
    0x0000_0000_8000_8009, 0x0000_0000_8000_0001,
    0x0000_0000_8000_000A, 0x8000_0000_8000_8008,
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

struct Keccak {
    message: Vec<u8>,
    state: [[u64; 5]; 5], // A, S
    b: usize,
    c: usize, // capacity
    l: usize,
    n: usize,
    r: usize, // bitrate
    w: usize, // lane size
}

impl Keccak {
    pub const fn new() -> Self {
        // > 1.4  The Keccak sponge functions
        // > The default value for r is 1600 − c and the default value for c is 576:
        // >> b = r + c = 1600
        // >> w = b/25 = 1600/25 = 64
        // >> w = 2^l => l = 6
        Self {
            message: Vec::new(),
            state: [[0; 5]; 5],
            b: 1600,
            c: 576,
            l: 6,
            n: 1024,
            r: 1024,
            w: 64,
        }
    }
    fn set_params(&mut self, r: usize, c: usize, n: usize) {
        if r % 8 != 0 {
            panic!("r must be a multiple of 8 in this implementation.");
        }
        if n % 8 != 0 {
            panic!("output length must be a multiple of 8.");
        }
        self.r = r;
        self.c = c;
        self.n = n;
        self.b = r + c;
        self.w = self.b / 25;
        self.l = (self.w as f32).log2() as usize;
    }
    // 1000...0001 Style
    fn padding(&mut self, suffix: u8) {
        let message_length = self.message.len() / 8;
        let rate_length = self.r / 8;
        self.message.push(suffix);
        // [byte]: rate_length - message_length - 2(0x80 and 0x01)
        let zero_padding_length = rate_length as i128 - message_length as i128 - 2;
        match zero_padding_length.cmp(&0) {
            Ordering::Greater => {
                self.message
                    .append(&mut vec![0; zero_padding_length as usize]);
            }
            Ordering::Less => {
                self.message.append(&mut vec![
                    0;
                    rate_length
                        - zero_padding_length.abs() as usize
                            % rate_length
                ]);
            }
            Ordering::Equal => (),
        }
        self.message.push(0x01);
        for o in &self.message {
            print!("{:02x}", o);
        }
    }
    fn keccak_f(&mut self) {
        fn round(mut a: [[u64; 5]; 5], rc: u64) -> [[u64; 5]; 5] {
            let mut b = vec![vec![0; 5]; 5];
            let mut c = vec![0; 5];
            let mut d = vec![0; 5];
            // Theta step
            for x in 0..5 {
                c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
            }
            for x in 0..5 {
                d[x] = c[(x as isize - 1) as usize %5] ^ c[(x + 1)%5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    a[x][y] ^= d[x];
                }
            }
            // Rho and Pi step
            for x in 0..5 {
                for y in 0..5 {
                    b[y][(2 * x + 3 * y)%5] = a[x][y].rotate_left(R[x][y]);
                }
            }
            // Chi step
            for x in 0..5 {
                for y in 0..5 {
                    a[x][y] = b[x][y] ^ (!b[(x + 1)%5][y] & b[(x + 2)%5][y]);
                }
            }
            // Iota step
            a[0][0] = a[0][0] ^ rc;
            // Return A
            a
        }
        let n = 12 + 2 * self.l;
        for i in 0..n {
            // A: self.state
            self.state = round(self.state, RC[i]);
            // println!("Round {}/{}", i+1,n);
            // for x in 0..5 {
            //     println!("{:016x} {:016x} {:016x} {:016x} {:016x}", self.state[x][0],self.state[x][1],self.state[x][2],self.state[x][3],self.state[x][4]);
            // }
        }
    }
    fn hash(&mut self, message: &[u8]) -> Vec<u8> {
        self.message(message);
        self.padding(0x06);
        // Initialize (S initialized in Self::new())
        // Absorbing phase
        let word_size = self.r / 8;
        let word_block_length = self.message.len() / word_size;
        println!("\n{}, {}",word_size,word_block_length);
        for i in 0..word_block_length {
            let mut pi = self.message[i * word_size..(i + 1) * word_size].to_vec();
            // #[cfg(target_endian = "little")]
            // {
            //     pi.reverse();
            // }
            for x in 0..5 {
                for y in 0..5 {
                    if x + 5 * y < (self.r / self.w) {
                        self.state[x][y] ^= pi[(x + 5 * y)%5] as u64;
                    }
                }
            }
            self.keccak_f();
        }
        println!("{:?}", self.state);
        // Squeezing phase
        let mut z = Vec::new();
        for _ in 0..(self.n / word_size) {
            for x in 0..5 {
                for y in 0..5 {
                    if x + 5 * y < (self.r / self.w) {
                        // trim S[x][y] to r bit and push to z.
                        let mut trimmed_s =
                            self.state[x][y].to_be_bytes()[(64 - self.w)..8].to_vec();
                        z.append(&mut trimmed_s);
                    }
                }
            }
            self.keccak_f();
        }
        z[0..self.n/8].to_vec()
    }
}

impl Message for Keccak {
    // Set Message
    impl_message!(self, u64);
}
