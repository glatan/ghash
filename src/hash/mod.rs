mod blake;
mod keccak;
mod md2;
mod md4;
mod md5;
mod ripemd;
mod sha0;
mod sha1;
mod sha2;
mod sha3;

pub use blake::{Blake224, Blake256, Blake28, Blake32, Blake384, Blake48, Blake512, Blake64};
pub use keccak::{Keccak224, Keccak256, Keccak384, Keccak512};
pub use md2::Md2;
pub use md4::Md4;
pub use md5::Md5;
pub use ripemd::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
pub use sha0::Sha0;
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

// MD4 Style Padding
#[macro_export(local)]
macro_rules! impl_md4_padding {
    // from_bytes
    //// from_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// from_le_bytes: Others
    // to_bytes
    //// to_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// to_le_bytes: Others
    (u32 => $self:ident, $from_bytes:ident, $to_bytes:ident) => {
        fn padding(&mut $self, message: &[u8]) {
            let mut m = message.to_vec();
            let l = message.len();
            // append 0b1000_0000
            m.push(0x80);
            // 64 - 1(0x80) - 8(l) = 55
            match (l % 64).cmp(&55) {
                Ordering::Greater => {
                    m.append(&mut vec![0; 64 + 55 - (l % 64)]);
                }
                Ordering::Less => {
                    m.append(&mut vec![0; 55 - (l % 64)]);
                }
                Ordering::Equal => (),
            }
            // append message length
            m.append(&mut (8 * l as u64).$to_bytes().to_vec());
            // create 32 bit-words from input bytes(and appending bytes)
            for i in (0..m.len()).filter(|i| i % 4 == 0) {
                $self.word_block.push(u32::$from_bytes([
                    m[i],
                    m[i + 1],
                    m[i + 2],
                    m[i + 3],
                ]));
            }
        }
    };
    // from_bytes
    //// from_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// from_le_bytes: Others
    // to_bytes
    //// to_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// to_le_bytes: Others
    (u64 => $self:ident, $from_bytes:ident, $to_bytes:ident) => {
        fn padding(&mut $self, message: &[u8]) {
            let mut m = message.to_vec();
            let l = message.len();
            // append 0b1000_0000
            m.push(0x80);
            // 128 - 1(0x80) - 16(l) = 111
            match (l % 128).cmp(&111) {
                Ordering::Greater => {
                    m.append(&mut vec![0; 128 + 111 - (l % 128)]);
                }
                Ordering::Less => {
                    m.append(&mut vec![0; 111 - (l % 128)]);
                }
                Ordering::Equal => (),
            }
            // append message length
            m.append(&mut (8 * l as u128).$to_bytes().to_vec());
            // create 64 bit-words from input bytes(and appending bytes)
            for i in (0..m.len()).filter(|i| i % 8 == 0) {
                $self.word_block.push(u64::$from_bytes([
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
    };
}

pub trait Hash<T = Self> {
    fn hash_to_bytes(message: &[u8]) -> Vec<u8>;
    fn hash_to_lowerhex(message: &[u8]) -> String {
        Self::hash_to_bytes(message)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
    fn hash_to_upperhex(message: &[u8]) -> String {
        Self::hash_to_bytes(message)
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect()
    }
}

#[cfg(test)]
trait Test<T = Self>
where
    T: Hash,
{
    fn compare_bytes(message: &[u8], expected: &str) {
        fn hex_to_bytes(s: &str) -> Vec<u8> {
            // 上位4ビット
            let s1: Vec<u8> = s
                .chars()
                .by_ref()
                .enumerate()
                .filter(|(i, _)| i % 2 == 0)
                .map(|(_, c)| (c.to_digit(16).unwrap() as u8) << 4)
                .collect();
            // 下位4ビット
            let s2: Vec<u8> = s
                .chars()
                .by_ref()
                .enumerate()
                .filter(|(i, _)| i % 2 == 1)
                .map(|(_, c)| c.to_digit(16).unwrap() as u8)
                .collect();
            if s1.len() != s2.len() {
                unreachable!();
            }
            let bytes = {
                let mut bytes: Vec<u8> = Vec::new();
                for i in 0..s1.len() {
                    bytes.push((s1[i] & 0b1111_0000) | (s2[i] & 0b0000_1111));
                }
                bytes
            };
            bytes
        }
        assert_eq!(T::hash_to_bytes(message), hex_to_bytes(expected));
    }
    fn compare_lowerhex(message: &[u8], expected: &str) {
        fn to_lowerhex(s: &str) -> String {
            let mut lower = s.to_string();
            if s.is_ascii() {
                lower.make_ascii_lowercase();
                lower
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_lowerhex(message), to_lowerhex(expected));
    }
    fn compare_upperhex(message: &[u8], expected: &str) {
        fn to_upperhex(s: &str) -> String {
            let mut upper = s.to_string();
            if s.is_ascii() {
                upper.make_ascii_uppercase();
                upper
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_upperhex(message), to_upperhex(expected));
    }
}
