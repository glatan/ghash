// MD4 Style Padding
#[macro_export]
macro_rules! impl_md4_padding {
    // from_bytes
    //// from_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// from_le_bytes: Others
    // to_bytes
    //// to_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// to_le_bytes: Others
    (u32 => $self:ident, $from_bytes:ident, $to_bytes:ident) => {
        fn padding(&mut $self, message: &[u8]) {
            let mut m = message.to_vec();
            let l = message.len();
            // append 0b1000_0000
            m.push(0x80);
            // 64 - 1(0x80) - 8(l) = 55
            match (l % 64).cmp(&55) {
                Ordering::Greater => {
                    m.append(&mut vec![0; 64 + 55 - (l % 64)]);
                }
                Ordering::Less => {
                    m.append(&mut vec![0; 55 - (l % 64)]);
                }
                Ordering::Equal => (),
            }
            // append message length
            m.append(&mut (8 * l as u64).$to_bytes().to_vec());
            // create 32 bit-words from input bytes(and appending bytes)
            for i in (0..m.len()).filter(|i| i % 4 == 0) {
                $self.word_block.push(u32::$from_bytes([
                    m[i],
                    m[i + 1],
                    m[i + 2],
                    m[i + 3],
                ]));
            }
        }
    };
    // from_bytes
    //// from_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// from_le_bytes: Others
    // to_bytes
    //// to_be_bytes: SHA-{0, 1, 2}, BLAKE
    //// to_le_bytes: Others
    (u64 => $self:ident, $from_bytes:ident, $to_bytes:ident) => {
        fn padding(&mut $self, message: &[u8]) {
            let mut m = message.to_vec();
            let l = message.len();
            // append 0b1000_0000
            m.push(0x80);
            // 128 - 1(0x80) - 16(l) = 111
            match (l % 128).cmp(&111) {
                Ordering::Greater => {
                    m.append(&mut vec![0; 128 + 111 - (l % 128)]);
                }
                Ordering::Less => {
                    m.append(&mut vec![0; 111 - (l % 128)]);
                }
                Ordering::Equal => (),
            }
            // append message length
            m.append(&mut (8 * l as u128).$to_bytes().to_vec());
            // create 64 bit-words from input bytes(and appending bytes)
            for i in (0..m.len()).filter(|i| i % 8 == 0) {
                $self.word_block.push(u64::$from_bytes([
                    m[i],
                    m[i + 1],
                    m[i + 2],
                    m[i + 3],
                    m[i + 4],
                    m[i + 5],
                    m[i + 6],
                    m[i + 7],
                ]));
            }
        }
    };
}
