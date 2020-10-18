#[macro_export]
macro_rules! uint_from_bytes {
    (u32 => $i:expr, $block:expr, $bytes:expr, $from_bytes:ident) => {
        $block[$i] = u32::$from_bytes([
            $bytes[$i * 4],
            $bytes[$i * 4 + 1],
            $bytes[$i * 4 + 2],
            $bytes[$i * 4 + 3],
        ]);
    };
    (u64 => $i:expr, $block:expr, $bytes:expr, $from_bytes:ident) => {
        $block[$i] = u64::$from_bytes([
            $bytes[$i * 8],
            $bytes[$i * 8 + 1],
            $bytes[$i * 8 + 2],
            $bytes[$i * 8 + 3],
            $bytes[$i * 8 + 4],
            $bytes[$i * 8 + 5],
            $bytes[$i * 8 + 6],
            $bytes[$i * 8 + 7],
        ]);
    };
}

// main flow for MD4, MD5, RIPEMD-{128, 160, 256, 320}, SHA-0, SHA-1 and SHA-2
#[macro_export]
macro_rules! impl_md_flow {
    // $self: T, $message: input bytes
    // $from_bytes
    //// from_be_bytes: SHA-{0, 1, 2}
    //// from_le_bytes: Others
    // $to_bytes
    //// to_be_bytes: SHA-{0, 1, 2}
    //// to_le_bytes: Others
    // u32
    // 64 - 1(0x80) - 8(l) = 55
    // u64
    // 128 - 1(0x80) - 16(l) = 111
    (u32 => $self:expr, $message:ident, $from_bytes:ident, $to_bytes:ident) => {
        let l = $message.len();
        let mut block = [0u32; 16];
        if l >= 64 {
            $message.chunks_exact(64).for_each(|bytes| {
                uint_from_bytes!(u32 => 0, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 1, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 2, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 3, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 4, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 5, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 6, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 7, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 8, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 9, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 10, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 11, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 12, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 13, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 14, block, bytes, $from_bytes);
                uint_from_bytes!(u32 => 15, block, bytes, $from_bytes);
                $self.compress(&block);
            });
        } else if l == 0 {
            $self.compress(&[
                u32::$from_bytes([0x80, 0, 0, 0]),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
        }
        if l != 0 {
            let offset = (l / 64) * 64;
            let remainder = l % 64;
            match (l % 64).cmp(&55) {
                Ordering::Greater => {
                    // two blocks
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[120..].copy_from_slice(&(8 * l as u64).$to_bytes());
                    byte_block.chunks_exact(64).for_each(|bytes| {
                        uint_from_bytes!(u32 => 0, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 1, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 2, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 3, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 4, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 5, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 6, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 7, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 8, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 9, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 10, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 11, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 12, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 13, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 14, block, bytes, $from_bytes);
                        uint_from_bytes!(u32 => 15, block, bytes, $from_bytes);
                        $self.compress(&block);
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 64];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[56..].copy_from_slice(&(8 * l as u64).$to_bytes());
                    uint_from_bytes!(u32 => 0, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 1, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 2, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 3, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 4, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 5, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 6, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 7, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 8, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 9, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 10, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 11, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 12, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 13, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 14, block, byte_block, $from_bytes);
                    uint_from_bytes!(u32 => 15, block, byte_block, $from_bytes);
                    $self.compress(&block);
                }
            }
        }
    };
    (u64 => $self:expr, $message:ident, $from_bytes:ident, $to_bytes:ident) => {
        let l = $message.len();
        let mut block = [0u64; 16];
        if l >= 128 {
            $message.chunks_exact(128).for_each(|bytes| {
                uint_from_bytes!(u64 => 0, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 1, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 2, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 3, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 4, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 5, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 6, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 7, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 8, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 9, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 10, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 11, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 12, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 13, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 14, block, bytes, $from_bytes);
                uint_from_bytes!(u64 => 15, block, bytes, $from_bytes);
                $self.compress(&block);
            });
        } else if l == 0 {
            $self.compress(&[
                u64::$from_bytes([0x80, 0, 0, 0, 0, 0, 0, 0]),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
        }
        if l != 0 {
            let offset = (l / 128) * 128;
            let remainder = l % 128;
            match (l % 128).cmp(&111) {
                Ordering::Greater => {
                    // two blocks
                    let mut byte_block = [0u8; 256];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[240..].copy_from_slice(&(8 * l as u128).$to_bytes());
                    byte_block.chunks_exact(128).for_each(|bytes| {
                        uint_from_bytes!(u64 => 0, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 1, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 2, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 3, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 4, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 5, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 6, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 7, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 8, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 9, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 10, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 11, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 12, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 13, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 14, block, bytes, $from_bytes);
                        uint_from_bytes!(u64 => 15, block, bytes, $from_bytes);
                        $self.compress(&block);
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[112..].copy_from_slice(&(8 * l as u128).$to_bytes());
                    uint_from_bytes!(u64 => 0, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 1, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 2, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 3, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 4, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 5, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 6, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 7, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 8, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 9, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 10, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 11, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 12, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 13, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 14, block, byte_block, $from_bytes);
                    uint_from_bytes!(u64 => 15, block, byte_block, $from_bytes);
                    $self.compress(&block);
                }
            }
        }
    };
}

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
    ($self:ident, $module_name:ident, $test_cases:ident, $hasher:expr) => {
        mod tests {
            mod $module_name {
                use super::super::$self;
                use super::super::$test_cases;
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
            }
        }
    };
}
