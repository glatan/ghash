#[macro_export]
macro_rules! impl_test {
    ($self:ident, $test_name:ident, $test_cases:ident, $hasher:expr) => {
        mod $test_name {
            use super::$self;
            use super::$test_cases;
            use util::Hash;
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
    ($module:ident, $T:ident, $test_cases:ident, $hasher:expr) => {
        #[allow(non_snake_case)]
        mod $T {
            use super::$test_cases;
            use util::Hash;
            use $module::$T;
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
            use util::Hash;
            use $module::$T;
            #[bench]
            #[allow(non_snake_case)]
            fn B064(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[0; 64]));
                b.bytes = 64;
            }
            #[bench]
            #[allow(non_snake_case)]
            fn KB256(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[0; 1024 * 256]));
                b.bytes = 1024 * 256;
            }
            #[bench]
            #[allow(non_snake_case)]
            fn MB004(b: &mut Bencher) {
                b.iter(|| $T::default().hash_to_bytes(&[0; 1024 * 1024 * 4]));
                b.bytes = 1024 * 1024 * 4;
            }
        }
    };
}
