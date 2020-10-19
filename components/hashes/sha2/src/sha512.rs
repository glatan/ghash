use super::Sha2;
use std::cmp::Ordering;
use utils::{impl_md_flow, uint_from_bytes, Hash};

pub struct Sha512(Sha2<u64>);

impl Sha512 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Sha512 {
    #[rustfmt::skip]
    fn default() -> Self {
        Self(Sha2::<u64>::new([
            0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
        ]))
    }
}

impl Hash for Sha512 {
    fn hash_to_bytes(&mut self, message: &[u8]) -> Vec<u8> {
        impl_md_flow!(u64=> self.0, message, from_be_bytes, to_be_bytes);
        self.0
            .status
            .iter()
            .flat_map(|word| word.to_be_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512;
    use utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 11] = [
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
        (
            "abc".as_bytes(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
        (
            &[],
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            &[0; 111],
            "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c",
        ),
        (
            &[0; 112],
            "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952",
        ),
        (
            &[0; 113],
            "0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544",
        ),
        (
            &[0; 122],
            "4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f",
        ),
        (
            &[0; 1000],
            "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76",
        ),
        (
            &[0x41; 1000],
            "329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af",
        ),
        (
            &[0x55; 1005],
            "59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161",
        ),
        (
            &[0; 1000000],
            "ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed"
        ),
        // TOO BIG!
        // 0x20000000 (536870912) bytes of 0x5a ‘Z’
        // 0x41000000 (1090519040) bytes of zeros
        // 0x6000003e (1610612798) bytes of 0x42 ‘B’
    ];
    impl_test!(Sha512, official, OFFICIAL, Sha512::default());
}
