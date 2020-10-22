#[macro_export]
macro_rules! impl_test {
    ($self:ident, $test_name:ident, $test_cases:ident, $hasher:expr) => {
        mod $test_name {
            use super::$self;
            use super::$test_cases;
            use utils::Hash;
            #[test]
            fn lower_hex() {
                for (m, e) in $test_cases.iter() {
                    assert_eq!($hasher.hash_to_lowerhex(m), *e);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_short_msg_kat {
    ($test_cases:ident, $hasher:expr) => {
        use utils::Hash;
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
        #[test]
        fn short_msg_kat() {
            for (m, e) in $test_cases.iter() {
                assert_eq!($hasher.hash_to_lowerhex(&hex_to_bytes(m)), *e);
            }
        }
    };
}

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
