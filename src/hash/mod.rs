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
