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
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8>;
    fn hash_to_lowerhex(&mut self, message: &[u8]) -> String {
        self.hash_to_bytes(message)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
    fn hash_to_upperhex(&mut self, message: &[u8]) -> String {
        self.hash_to_bytes(message)
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect()
    }
}

#[cfg(test)]
trait Test<T = Self>
where
    T: Default + Hash,
{
    fn compare_lowerhex(hasher: &mut T, message: &[u8], expected: &str) {
        assert_eq!(hasher.hash_to_lowerhex(message), expected);
    }
}
