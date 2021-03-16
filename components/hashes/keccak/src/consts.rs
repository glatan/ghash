#[rustfmt::skip]
pub(crate) const RC1600: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
    0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088,
    0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B,
    0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
    0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
    0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];
#[rustfmt::skip]
pub(crate) const RC800: [u32; 22] = [
    0x0000_0001, 0x0000_8082,
    0x0000_808A, 0x8000_8000,
    0x0000_808B, 0x8000_0001,
    0x8000_8081, 0x0000_8009,
    0x0000_008A, 0x0000_0088,
    0x8000_8009, 0x8000_000A,
    0x8000_808B, 0x0000_008B,
    0x0000_8089, 0x0000_8003,
    0x0000_8002, 0x0000_0080,
    0x0000_800A, 0x8000_000A,
    0x8000_8081, 0x0000_8080,
];
#[rustfmt::skip]
pub(crate) const RC400: [u16; 20] = [
    0x0001, 0x8082, 0x808A, 0x8000,
    0x808B, 0x0001, 0x8081, 0x8009,
    0x008A, 0x0088, 0x8009, 0x000A,
    0x808B, 0x008B, 0x8089, 0x8003,
    0x8002, 0x0080, 0x800A, 0x000A,
];
#[rustfmt::skip]
pub(crate) const RC200: [u8; 18] = [
    0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01,
    0x81, 0x09, 0x8A, 0x88, 0x09, 0x0A,
    0x8B, 0x8B, 0x89, 0x03, 0x02, 0x80,
];

pub(crate) const R1600: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub(crate) const R800: [[u32; 5]; 5] = [
    [0, 4, 3, 9, 18],
    [1, 12, 10, 13, 2],
    [30, 6, 11, 15, 29],
    [28, 23, 25, 21, 24],
    [27, 20, 7, 8, 14],
];
pub(crate) const R400: [[u32; 5]; 5] = [
    [0, 1, 14, 12, 11],
    [4, 12, 6, 7, 4],
    [3, 10, 11, 9, 7],
    [9, 13, 15, 5, 8],
    [2, 2, 13, 8, 14],
];
pub(crate) const R200: [[u32; 5]; 5] = [
    [0, 1, 6, 4, 3],
    [4, 4, 6, 7, 4],
    [3, 2, 3, 1, 7],
    [1, 5, 7, 5, 0],
    [2, 2, 5, 0, 6],
];
