#![feature(test)]

macro_rules! impl_benchmark {
    ($T:ident) => {
        #[allow(non_snake_case)]
        mod $T {
            extern crate test;
            use ghash::{$T, Hash};
            use test::Bencher;
            #[bench]
            #[allow(non_snake_case)]
            fn B0(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn B512(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 512]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB1(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB2(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 2]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB4(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 4]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB16(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 16]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB64(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 64]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB512(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 512]))
            }
            #[bench]
            #[allow(non_snake_case)]
            fn MB1(b: &mut Bencher) {
                b.iter(|| $T::hash_to_bytes(&[0; 1024 * 1024]))
            }
        }
    };
}

impl_benchmark!(Blake224);
impl_benchmark!(Blake256);
impl_benchmark!(Blake384);
impl_benchmark!(Blake512);
impl_benchmark!(Keccak224);
impl_benchmark!(Keccak256);
impl_benchmark!(Keccak384);
impl_benchmark!(Keccak512);
impl_benchmark!(Ripemd128);
impl_benchmark!(Ripemd160);
impl_benchmark!(Ripemd256);
impl_benchmark!(Ripemd320);
impl_benchmark!(Md2);
impl_benchmark!(Md4);
impl_benchmark!(Md5);
impl_benchmark!(Sha0);
impl_benchmark!(Sha1);
impl_benchmark!(Sha224);
impl_benchmark!(Sha256);
impl_benchmark!(Sha384);
impl_benchmark!(Sha512);
impl_benchmark!(Sha512Trunc224);
impl_benchmark!(Sha512Trunc256);
impl_benchmark!(Sha3_224);
impl_benchmark!(Sha3_256);
impl_benchmark!(Sha3_384);
impl_benchmark!(Sha3_512);
