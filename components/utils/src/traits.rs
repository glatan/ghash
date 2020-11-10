use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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
    use alloc::vec;
    use alloc::vec::Vec;

    use super::Hash;

    struct Tester(Vec<u8>);
    impl Tester {
        fn new(bytes: Vec<u8>) -> Tester {
            Self(bytes)
        }
    }
    impl Hash for Tester {
        fn hash_to_bytes(&mut self, _: &[u8]) -> Vec<u8> {
            self.0.clone()
        }
    }

    #[test]
    fn lower_hex() {
        assert_eq!(
            Tester::new(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]).hash_to_lowerhex(&[]),
            "0123456789abcdef"
        );
        assert_eq!(Tester::new(vec![]).hash_to_lowerhex(&[]), "");
    }
    #[test]
    fn upper_hex() {
        assert_eq!(
            Tester::new(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]).hash_to_upperhex(&[]),
            "0123456789ABCDEF"
        );
        assert_eq!(Tester::new(vec![]).hash_to_upperhex(&[]), "");
    }
}
