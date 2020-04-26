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
            fn input(&mut self, message: &[u8]) {
                match message.len().checked_mul(8) {
                    Some(_) => {
                        // input bit length is less than usize::MAX
                        match mem::size_of::<usize>().cmp(&mem::size_of::<$LimitT>()) {
                            Ordering::Equal | Ordering::Less => {
                                // input type limit is less than hash function limit
                                self.message = message.to_vec();
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
impl_input!(Md2, usize);
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

#[macro_export(local)]
macro_rules! impl_md4_padding {
    (u32 => $self:ident, $from_bytes:ident, $to_bytes:ident, $padding_base:expr, $optional_padding:block) => {
        fn padding(&mut $self) {
            let message_length = $self.message.len();
            // 入力末尾に0x80を追加(0b1000_0000)
            $self.message.push(0x80);
            // [byte]: 64 - 8(message_length) - 1(0x80) - 1(0x00 or 0x01) = 54 => BLAKE
            // [byte]: 64 - 8(message_length) - 1(0x80) = 55 => Others
            let padding_length = $padding_base - (message_length as i128);
            match padding_length.cmp(&0) {
                Ordering::Greater => {
                    $self.message.append(&mut vec![0; padding_length as usize]);
                }
                Ordering::Less => {
                    $self.message
                        .append(&mut vec![0; 64 - (padding_length.abs() % 64) as usize]);
                }
                Ordering::Equal => (),
            }
            // for BLAKE padding
            // BLAKE-224 => push 0x00
            // BLAKE-256 => push 0x01
            $optional_padding
            // 入力データの長さを追加
            $self.message
                .append(&mut (8 * message_length as u64).$to_bytes().to_vec());
            // バイト列からワードブロックを生成
            for i in (0..$self.message.len()).filter(|i| i % 4 == 0) {
                $self.word_block.push(u32::$from_bytes([
                    $self.message[i],
                    $self.message[i + 1],
                    $self.message[i + 2],
                    $self.message[i + 3],
                ]));
            }
        }
    };
    (u64 => $self:ident, $from_bytes:ident, $to_bytes:ident, $padding_base:expr, $optional_padding:block) => {
        fn padding(&mut $self) {
            let input_length = $self.message.len();
            // word_block末尾に0x80を追加(0b1000_0000)
            $self.message.push(0x80);
            // [byte]: 128 - 16(input_length) - 1(0x80) - 1(0x00 or 0x00)= 110 => BLAKE
            // [byte]: 128 - 16(input_length) - 1(0x80) = 111 => Others
            let padding_length = $padding_base - (input_length as i128);
            match padding_length.cmp(&0) {
                Ordering::Greater => {
                    $self.message.append(&mut vec![0; padding_length as usize]);
                }
                Ordering::Less => {
                    $self.message
                        .append(&mut vec![0; 128 - (padding_length.abs() % 128) as usize]);
                }
                Ordering::Equal => (),
            }
            // for BLAKE padding
            // BLAKE-384 => push 0x00
            // BLAKE-512 => push 0x01
            $optional_padding
            // 入力データの長さを追加
            $self.message
                .append(&mut (8 * input_length as u128).$to_bytes().to_vec());
            // 64bitワードにしてpush
            for i in (0..$self.message.len()).filter(|i| i % 8 == 0) {
                $self.word_block.push(u64::$from_bytes([
                    $self.message[i],
                    $self.message[i + 1],
                    $self.message[i + 2],
                    $self.message[i + 3],
                    $self.message[i + 4],
                    $self.message[i + 5],
                    $self.message[i + 6],
                    $self.message[i + 7],
                ]));
            }
        }
    };
}

pub trait Hash {
    fn hash(message: &[u8]) -> Vec<u8>;
    fn hash_to_lowercase(message: &[u8]) -> String {
        Self::hash(message)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
    fn hash_to_uppercase(message: &[u8]) -> String {
        Self::hash(message)
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
        assert_eq!(T::hash(message), hex_to_bytes(expected));
    }
    fn compare_lowercase(message: &[u8], expected: &str) {
        fn to_lowercase(s: &str) -> String {
            let mut lower = s.to_string();
            if s.is_ascii() {
                lower.make_ascii_lowercase();
                lower
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_lowercase(message), to_lowercase(expected));
    }
    fn compare_uppercase(message: &[u8], expected: &str) {
        fn to_upperrcase(s: &str) -> String {
            let mut upper = s.to_string();
            if s.is_ascii() {
                upper.make_ascii_uppercase();
                upper
            } else {
                unreachable!()
            }
        }
        assert_eq!(T::hash_to_uppercase(message), to_upperrcase(expected));
    }
}
