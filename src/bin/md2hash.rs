use std::io;
use std::io::BufRead;

const BLOCKSIZE: usize = 16;
const STABLE: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
];

struct Md2Ctx {
    /*
    word_block {
        input + padding_byte : 16*n bytes
        +
        checksum : 16 bytes
    }
    */
    word_block: Vec<u8>,
    state: [u8; 48],
}

impl Md2Ctx {
    fn new(input: Vec<u8>) -> Md2Ctx {
        Md2Ctx {
            word_block: input,
            state: [0; 48],
        }
    }
    fn padding(&mut self) -> &mut Md2Ctx {
        /*
        padding_byte: self.dataを16の整数倍長に調整するための値
        */
        let message_length = self.word_block.len();
        let padding_byte = (BLOCKSIZE - (message_length % BLOCKSIZE)) as u8;
        self.word_block
            .append(&mut vec![padding_byte; padding_byte as usize]);
        self
    }
    fn add_check_sum(&mut self) -> &mut Md2Ctx {
        let word_block_length = self.word_block.len() / BLOCKSIZE;
        let mut checksum = vec![0; 16];
        let (mut c, mut l) = (0, 0);

        for i in 0..word_block_length {
            for j in 0..16 {
                c = self.word_block[16 * i + j] as usize;
                checksum[j] ^= STABLE[c ^ l];
                l = checksum[j] as usize;
                self.word_block.push(checksum[j] as u8);
            }
        }
        self
    }
    fn round(&mut self) -> &mut Md2Ctx {
        let word_block_length = self.word_block.len() / BLOCKSIZE;

        for i in 0..word_block_length {
            for j in 0..16 {
                self.state[j + 16] = self.word_block[16 * i + j];
                self.state[j + 32] = self.state[j + 16] ^ self.state[j];
            }
            let mut t: usize = 0;
            for j in 0..18 {
                for k in 0..48 {
                    self.state[k] ^= STABLE[t];
                    t = self.state[k] as usize;
                }
                t = (t + j) % 256;
            }
        }
        self
    }
    fn print_hash(&mut self) {
        let hash: Vec<String> = self.state[0..16]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();
        println!("md2hash: \"{}\"", hash.join(""));
    }
}

fn main() {
    let input_data = {
        let mut input_data = String::new();
        io::stdin().lock().read_line(&mut input_data).unwrap();
        input_data.trim_right().as_bytes().to_vec()
    };
    println!("input_data: {:?} bytes", input_data.len());
    Md2Ctx::new(input_data)
        .padding()
        .add_check_sum()
        .round()
        .print_hash();
}
