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
                for i in 0..16 {
                    block[i] = u32::$from_bytes([
                        bytes[i * 4],
                        bytes[i * 4 + 1],
                        bytes[i * 4 + 2],
                        bytes[i * 4 + 3],
                    ]);
                }
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
                        for i in 0..16 {
                            block[i] = u32::$from_bytes([
                                bytes[i * 4],
                                bytes[i * 4 + 1],
                                bytes[i * 4 + 2],
                                bytes[i * 4 + 3],
                            ]);
                        }
                        $self.compress(&block);
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 64];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[56..].copy_from_slice(&(8 * l as u64).$to_bytes());
                    for i in 0..16 {
                        block[i] = u32::$from_bytes([
                            byte_block[i * 4],
                            byte_block[i * 4 + 1],
                            byte_block[i * 4 + 2],
                            byte_block[i * 4 + 3],
                        ]);
                    }
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
                for i in 0..16 {
                    block[i] = u64::$from_bytes([
                        bytes[i * 8],
                        bytes[i * 8 + 1],
                        bytes[i * 8 + 2],
                        bytes[i * 8 + 3],
                        bytes[i * 8 + 4],
                        bytes[i * 8 + 5],
                        bytes[i * 8 + 6],
                        bytes[i * 8 + 7],
                    ]);
                }
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
                        for i in 0..16 {
                            block[i] = u64::$from_bytes([
                                bytes[i * 8],
                                bytes[i * 8 + 1],
                                bytes[i * 8 + 2],
                                bytes[i * 8 + 3],
                                bytes[i * 8 + 4],
                                bytes[i * 8 + 5],
                                bytes[i * 8 + 6],
                                bytes[i * 8 + 7],
                            ]);
                        }
                        $self.compress(&block);
                    });
                }
                Ordering::Less | Ordering::Equal => {
                    // one block
                    let mut byte_block = [0u8; 128];
                    byte_block[..remainder].copy_from_slice(&$message[offset..]);
                    byte_block[remainder] = 0x80;
                    byte_block[112..].copy_from_slice(&(8 * l as u128).$to_bytes());
                    for i in 0..16 {
                        block[i] = u64::$from_bytes([
                            byte_block[i * 8],
                            byte_block[i * 8 + 1],
                            byte_block[i * 8 + 2],
                            byte_block[i * 8 + 3],
                            byte_block[i * 8 + 4],
                            byte_block[i * 8 + 5],
                            byte_block[i * 8 + 6],
                            byte_block[i * 8 + 7],
                        ]);
                    }
                    $self.compress(&block);
                }
            }
        }
    };
}

// Zero-fill tests are generated by using this(https://gitlab.com/glatan/test-vector-generator-for-hash-functions).
#[macro_export]
macro_rules! impl_test {
    ($self:ident, $test_name:ident, $test_cases:ident, $hasher:expr) => {
        mod $test_name {
            use super::$self;
            use super::$test_cases;
            use crate::hash::Hash;
            #[test]
            fn lower_hex() {
                for (m, e) in $test_cases.iter() {
                    assert_eq!($hasher.hash_to_lowerhex(m), *e);
                }
            }
        }
    };
}
