#[macro_export]
macro_rules! impl_benchmark {
    ($module:ident, $T:ident) => {
        #[allow(non_snake_case)]
        mod $T {
            extern crate test;
            use test::Bencher;
            use utils::Hash;
            use $module::$T;
            #[bench]
            #[allow(non_snake_case)]
            fn B000(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[]));
                b.bytes = 0;
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB001(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[0; 1024]));
                b.bytes = 1024;
            }
            #[bench]
            #[allow(non_snake_case)]
            fn MB001(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[0; 1024 * 1024]));
                b.bytes = 1024 * 1024;
            }
        }
    };
}
