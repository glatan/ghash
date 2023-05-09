mod blake2b;
mod blake2s;

#[macro_export]
macro_rules! impl_blake2_short_msg_kat_with_key {
    ($module:ident, $T:ident, $test_cases:ident, $init:ident) => {
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
                for (m, p, e) in $test_cases.iter() {
                    let mut hasher = $T::$init(p.0, p.1, p.2, p.3);
                    assert_eq!(hasher.hash_to_lowerhex(&hex_to_bytes(m)), *e);
                }
            }
        }
    };
}
