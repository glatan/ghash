use std::io;
use std::io::BufRead;

const WORD_BUFFER: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

struct Round {}
impl Round {
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    fn round1(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8) -> u32 {
        a.wrapping_add(Round::f(b, c, d)).wrapping_add(k as u32).rotate_left(s as u32)
    }
    fn round2(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8) -> u32 {
        a.wrapping_add(Round::g(b, c, d)).wrapping_add(k as u32).wrapping_add(0x5A82_7999).rotate_left(s as u32)
    }
    fn round3(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8) -> u32 {
        a.wrapping_add(Round::h(b, c, d)).wrapping_add(k as u32).wrapping_add(0x6ED9_EBA1).rotate_left(s as u32)
    }
}

struct Md4Ctx {
    word_block: Vec<u8>,
    status: [u32; 4],
}

impl Md4Ctx {
    fn new(input: Vec<u8>) -> Md4Ctx {
        Md4Ctx {
            word_block: input,
            status: WORD_BUFFER,
        }
    }
    fn padding(&mut self) -> &mut Md4Ctx {
        // word_block末尾に0x80を追加
        self.word_block.push(0x80);
        let mut message_length = self.word_block.len();
        // (self.word_block.len() % 64)が56になるよう0を追加する数
        let padding_range = 56 - (message_length % 64);
        self.word_block.append(&mut vec![0; padding_range]);
        // 入力データの長さを追加
        let mut padding_length: Vec<u8> = {
            message_length *= 8;
            let b1: u8 = (message_length & 0xff) as u8;
            let b2: u8 = ((message_length.rotate_right(8)) & 0xff) as u8;
            let b3: u8 = ((message_length.rotate_right(16)) & 0xff) as u8;
            let b4: u8 = ((message_length.rotate_right(24)) & 0xff) as u8;
            let b5: u8 = ((message_length.rotate_right(32)) & 0xff) as u8;
            let b6: u8 = ((message_length.rotate_right(40)) & 0xff) as u8;
            let b7: u8 = ((message_length.rotate_right(48)) & 0xff) as u8;
            let b8: u8 = ((message_length.rotate_right(56)) & 0xff) as u8;
            vec![b1, b2, b3, b4, b5, b6, b7, b8]
        };
        self.word_block.append(&mut padding_length);
        self
    }
    fn round(&mut self) -> &mut Md4Ctx {
        let word_block_length = self.word_block.len() / 16;
        println!("{}", word_block_length);
        let (mut a, mut b, mut c, mut d);
        let mut x: [u8; 16] = [0; 16];
        for i in 0..word_block_length {
            for j in 0..16 {
                x[j] = self.word_block[16 * i + j];
            }
            a = self.status[0];
            b = self.status[1];
            c = self.status[2];
            d = self.status[3];
            // Round 1
            for &k in &[0, 4, 8, 12] {
                a = Round::round1(a, b, c, d, x[k], 3);
                b = Round::round1(d, a, b, c, x[k + 1], 7);
                c = Round::round1(c, d, a, b, x[k + 2], 11);
                d = Round::round1(b, c, d, a, x[k + 3], 19);
            }
            // Round 2
            for k in 0..4 {
                a = Round::round2(a, b, c, d, x[k], 3);
                b = Round::round2(d, a, b, c, x[k + 4], 5);
                c = Round::round2(c, d, a, b, x[k + 8], 9);
                d = Round::round2(b, c, d, a, x[k + 12], 13);
            }
            // Round 3
            for &k in &[0, 2, 1, 3] {
                a = Round::round3(a, b, c, d, x[k], 3);
                b = Round::round3(d, a, b, c, x[k + 8], 9);
                c = Round::round3(c, d, a, b, x[k + 4], 11);
                d = Round::round3(b, c, d, a, x[k + 12], 15);
            }
            self.status = [
                self.status[0].wrapping_add(a),
                self.status[1].wrapping_add(b),
                self.status[2].wrapping_add(c),
                self.status[3].wrapping_add(d),
            ];
        }
        self
    }
    fn print_hash(&mut self) {
        println!("status: {:?}", self.status);
        let hash: Vec<String> = self.status[0..4]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();
        println!("md4hash: \"{}\"", hash.join(""));
    }
}

fn main() {
    let input_data = {
        let mut input_data = String::new();
        io::stdin().lock().read_line(&mut input_data).unwrap();
        input_data.trim_right().as_bytes().to_vec()
    };
    println!("input_data: {:?}", input_data);
    Md4Ctx::new(input_data).padding().round().print_hash();
}
