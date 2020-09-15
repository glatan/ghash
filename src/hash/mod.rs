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
mod tests {
    use super::Hash;
    use crate::{Md5, Sha1, Sha256};

    #[test]
    fn compare_bytes() {
        assert_eq!(
            Md5::default().hash_to_bytes(&[]),
            vec![
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
        assert_eq!(
            Sha1::default().hash_to_bytes(&[]),
            vec![
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
        assert_eq!(
            Sha256::default().hash_to_bytes(&[]),
            vec![
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }
    #[test]
    fn compare_lowerhex() {
        assert_eq!(
            Md5::default().hash_to_lowerhex(&[]),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            Sha1::default().hash_to_lowerhex(&[]),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            Sha256::default().hash_to_lowerhex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn compare_upperhex() {
        assert_eq!(
            Md5::default().hash_to_upperhex(&[]),
            "D41D8CD98F00B204E9800998ECF8427E"
        );
        assert_eq!(
            Sha1::default().hash_to_upperhex(&[]),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            Sha256::default().hash_to_upperhex(&[]),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }
}
