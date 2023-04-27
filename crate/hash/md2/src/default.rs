use alloc::vec::Vec;

use util::Hash;

use crate::consts::STABLE;

macro_rules! init_state {
    ($self:expr, $block:expr, $( $i:expr ), +) => {
        $(
            $self.state[$i + 32] = $block[$i] ^ $self.state[$i];
        )*
    };
}

macro_rules! round {
    ($self:expr, $t:expr, $($i:expr), +) => {
        $(
            // このループを展開するとむしろ遅くなる
            // 多分ループ回数が大きすぎるのが問題(16 * 48 = 768回)
            for k in 0..48 {
                $self.state[k] ^= STABLE[$t as usize];
                $t = $self.state[k] as usize;
            }
            $t = ($t + $i) % 256;
        )*
    };
}

macro_rules! checksum_j {
    ($self:expr, $message:expr, $checksum:expr, $c:expr, $l:expr, $i:expr, $( $j:expr ), +) => {
        $(
            $c = $message[16 * $i + $j];
            $checksum[$j] ^= STABLE[($c ^ $l) as usize];
            $l = $checksum[$j];
        )*
    };
}

macro_rules! checksnum_i {
    ($self:expr, $block:expr, $checksum:expr, $c:expr, $l:expr, $( $i:expr ), +) => {
        $(
            $c = $block[$i];
            $checksum[$i] ^= STABLE[($c ^ $l) as usize];
            $l = $checksum[$i];
        )*
    };
}

pub struct Md2 {
    state: [u8; 48],
}

impl Md2 {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(unused_assignments)]
    fn compress(&mut self, block: &[u8]) {
        self.state[16..32].copy_from_slice(block);
        init_state!(self, block, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let mut t = 0;
        round!(self, t, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17);
    }
    #[allow(unused_assignments)]
    fn compress_checksum(&mut self, message: &[u8], padded_block: &[u8; 16]) {
        let mut checksum = [0u8; 16];
        let mut c;
        let mut l = 0;
        for i in 0..(message.len() / 16) {
            checksum_j!(
                self, message, checksum, c, l, i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15
            );
        }
        checksnum_i!(
            self,
            padded_block,
            checksum,
            c,
            l,
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15
        );
        self.compress(&checksum);
    }
}

impl Default for Md2 {
    fn default() -> Self {
        Self { state: [0; 48] }
    }
}

impl Hash for Md2 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        let len = message.len();
        if len == 0 {
            // First block is filled with 16 (padding bytes)
            self.compress(&[16; 16]);
            self.compress_checksum(&[], &[16; 16]);
        } else if len >= 16 {
            message
                .chunks_exact(16)
                .for_each(|block| self.compress(block));
        }
        if len != 0 {
            let paddlen = len % 16;
            let mut block = [(16 - paddlen) as u8; 16]; // padding
            let offset = len - paddlen;
            block[..paddlen].clone_from_slice(&message[offset..len]);
            self.compress(&block);
            self.compress_checksum(message, &block);
        }
        self.state[0..16].to_vec()
    }
}
