use std::cmp::Ordering;
use std::mem;

mod blake;
mod md2;
mod md4;
mod md5;
mod ripemd;
mod sha0;
mod sha1;
mod sha2;

use md4::Md4Padding;

pub use blake::{Blake224, Blake256, Blake384, Blake512};
pub use md2::Md2;
pub use md4::Md4;
pub use md5::Md5;
pub use ripemd::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
pub use sha0::Sha0;
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

use blake::Blake;
use sha2::Sha2;

macro_rules! impl_input {
    ($SelfT:ty, $LimitT:ty) => {
        impl $SelfT {
            fn input(&mut self, input: &[u8]) {
                match input.len().checked_mul(8) {
                    Some(_) => {
                        // input bit length is less than usize::MAX
                        match mem::size_of::<usize>().cmp(&mem::size_of::<$LimitT>()) {
                            Ordering::Equal | Ordering::Less => {
                                // input type limit is less than hash function limit
                                self.input = input.to_vec();
                            }
                            Ordering::Greater => {
                                // input bit length is greater than the hash function limit length
                                panic!(
                                    "{} takes a input of any length less than 2^{} bits",
                                    stringify!($SelfT),
                                    mem::size_of::<$LimitT>()
                                )
                            }
                        }
                    }
                    None => panic!(
                        "{} * 8 is greeter than usize::MAX",
                        mem::size_of::<$LimitT>()
                    ),
                }
            }
        }
    };
}

impl_input!(Blake::<u32>, u64);
impl_input!(Blake::<u64>, u128);
impl_input!(Md4, u64);
impl_input!(Md5, u64);
impl_input!(Ripemd128, u64);
impl_input!(Ripemd160, u64);
impl_input!(Ripemd256, u64);
impl_input!(Ripemd320, u64);
impl_input!(Sha0, u64);
impl_input!(Sha1, u64);
impl_input!(Sha2<u32>, u64);
impl_input!(Sha2<u64>, u128);

pub trait Hash {
    fn hash(input: &[u8]) -> Vec<u8>;
    fn hash_to_lowercase(input: &[u8]) -> String {
        Self::hash(input)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
    fn hash_to_uppercase(input: &[u8]) -> String {
        Self::hash(input)
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect()
    }
}

#[cfg(test)]
trait Test<T>
where
    T: Hash,
{
    fn compare_bytes(input: &[u8], expected: &str) {
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
        assert_eq!(T::hash(input), hex_to_bytes(expected));
    }
    fn compare_lowercase(input: &[u8], expected: &str) {
        fn to_lowercase(s: &str) -> String {
            let mut lower = s.to_string();
            if s.is_ascii() {
                lower.make_ascii_lowercase();
                lower
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_lowercase(input), to_lowercase(expected));
    }
    fn compare_uppercase(input: &[u8], expected: &str) {
        fn to_upperrcase(s: &str) -> String {
            let mut upper = s.to_string();
            if s.is_ascii() {
                upper.make_ascii_uppercase();
                upper
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_uppercase(input), to_upperrcase(expected));
    }
}
