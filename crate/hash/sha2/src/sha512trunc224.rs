use alloc::vec::Vec;

use util::Hash;

use super::{Sha2, H512_TRUNC224};

pub struct Sha512Trunc224(Sha2<u64>);

impl Sha512Trunc224 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512Trunc224 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new(H512_TRUNC224))
    }
}

impl Hash for Sha512Trunc224 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.sha2(message);
        self.0.status[0..4]
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .take(224 / 8) // (224 / 8) bytes
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512Trunc224;
    use dev_util::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
        (
            "abc".as_bytes(),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
        ),
    ];

    impl_test!(
        Sha512Trunc224,
        official,
        OFFICIAL,
        Sha512Trunc224::default()
    );
}
