mod md2;
mod md4;
mod md5;
mod sha0;
mod sha1;
mod sha2;

pub use md2::Md2;
pub use md4::Md4;
pub use md5::Md5;
pub use sha0::Sha0;
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

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
