#[rustfmt::skip]
pub(crate) const P224: [u32; 16] =[
    0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F,
    0x1011_1213, 0x1415_1617, 0x1819_1A1B, 0x1C1D_1E1F,
    0x2021_2223, 0x2425_2627, 0x2829_2A2B, 0x2C2D_2E2F,
    0x3031_3233, 0x2435_3637, 0x3839_3A3B, 0x3C3D_3E3F,
];
#[rustfmt::skip]
pub(crate) const P256: [u32; 16] =[
    0x4041_4243, 0x4445_4647, 0x4849_4A4B, 0x4C4D_4E4F,
    0x5051_5253, 0x5455_5657, 0x5859_5A5B, 0x5C5D_5E5F,
    0x6061_6263, 0x6465_6667, 0x6869_6A6B, 0x6C6D_6E6F,
    0x7071_7273, 0x7475_7677, 0x7879_7A7B, 0x7C7D_7E7F,
];
#[rustfmt::skip]
pub(crate) const P384: [u64; 16] =[
    0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F,
    0x1011_1213_1415_1617, 0x1819_1A1B_1C1D_1E1F,
    0x2021_2223_2425_2627, 0x2829_2A2B_2C2D_2E2F,
    0x3031_3233_2435_3637, 0x3839_3A3B_3C3D_3E3F,
    0x4041_4243_4445_4647, 0x4849_4A4B_4C4D_4E4F,
    0x5051_5253_5455_5657, 0x5859_5A5B_5C5D_5E5F,
    0x6061_6263_6465_6667, 0x6869_6A6B_6C6D_6E6F,
    0x7071_7273_7475_7677, 0x7879_7A7B_7C7D_7E7F,
];
#[rustfmt::skip]
pub(crate) const P512: [u64; 16] =[
    0x8081_8283_8485_8687, 0x8889_8A8B_8C8D_8E8F,
    0x9091_9293_9495_9697, 0x9899_9A9B_9C9D_9E9F,
    0xA0A1_A2A3_A4A5_A6A7, 0xA8A9_AAAB_ACAD_AEAF,
    0xB0B1_B2B3_B4B5_B6B7, 0xB8B9_BABB_BCBD_BEBF,
    0xC0C1_C2C3_C4C5_C6C7, 0xC8C9_CACB_CCCD_CECF,
    0xD0D1_D2D3_D4D5_D6D7, 0xD8D9_DADB_DCDD_DEDF,
    0xE0E1_E2E3_E4E5_E6E7, 0xE8E9_EAEB_ECED_EEEF,
    0xF0F1_F2F3_F4F5_F6F7, 0xF8F9_FAFB_FCFD_FEFF
];

#[inline(always)]
pub(crate) const fn q256(x: &[u32; 8], y: &[u32; 8]) -> [u32; 8] {
    let mut z = [0u32; 8];
    let mut t = [0u32; 16];
    // First Latin Square
    t[0] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[2])
        .wrapping_add(x[4])
        .wrapping_add(x[7])
        .wrapping_add(0xAAAA_AAAA);
    t[1] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[7])
        .rotate_left(5);
    t[2] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[4])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(11);
    t[3] = x[2]
        .wrapping_add(x[3])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(13);
    t[4] = x[1]
        .wrapping_add(x[2])
        .wrapping_add(x[3])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .rotate_left(17);
    t[5] = x[0]
        .wrapping_add(x[2])
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[5])
        .rotate_left(19);
    t[6] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(29);
    t[7] = x[2]
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .rotate_left(31);
    t[8] = t[3] ^ t[5] ^ t[6];
    t[9] = t[2] ^ t[5] ^ t[6];
    t[10] = t[2] ^ t[3] ^ t[5];
    t[11] = t[0] ^ t[1] ^ t[4];
    t[12] = t[0] ^ t[4] ^ t[7];
    t[13] = t[1] ^ t[6] ^ t[7];
    t[14] = t[2] ^ t[3] ^ t[4];
    t[15] = t[0] ^ t[1] ^ t[7];
    // Second Orthogonal Latin Square
    t[0] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[2])
        .wrapping_add(y[5])
        .wrapping_add(y[7])
        .wrapping_add(0x5555_5555);
    t[1] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .rotate_left(3);
    t[2] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[2])
        .wrapping_add(y[3])
        .wrapping_add(y[5])
        .rotate_left(7);
    t[3] = y[2]
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(11);
    t[4] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[5])
        .rotate_left(17);
    t[5] = y[2]
        .wrapping_add(y[4])
        .wrapping_add(y[5])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(19);
    t[6] = y[1]
        .wrapping_add(y[2])
        .wrapping_add(y[5])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(23);
    t[7] = y[0]
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(29);
    z[5] = t[8].wrapping_add(t[3] ^ t[4] ^ t[6]);
    z[6] = t[9].wrapping_add(t[2] ^ t[5] ^ t[7]);
    z[7] = t[10].wrapping_add(t[4] ^ t[6] ^ t[7]);
    z[0] = t[11].wrapping_add(t[0] ^ t[1] ^ t[5]);
    z[1] = t[12].wrapping_add(t[2] ^ t[6] ^ t[7]);
    z[2] = t[13].wrapping_add(t[0] ^ t[1] ^ t[3]);
    z[3] = t[14].wrapping_add(t[0] ^ t[3] ^ t[4]);
    z[4] = t[15].wrapping_add(t[1] ^ t[2] ^ t[5]);
    z
}
#[inline(always)]
pub(crate) const fn q512(x: &[u64; 8], y: &[u64; 8]) -> [u64; 8] {
    let mut z = [0u64; 8];
    let mut t = [0u64; 16];
    // First Latin Square
    t[0] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[2])
        .wrapping_add(x[4])
        .wrapping_add(x[7])
        .wrapping_add(0xAAAA_AAAA_AAAA_AAAA);
    t[1] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[7])
        .rotate_left(5);
    t[2] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[4])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(19);
    t[3] = x[2]
        .wrapping_add(x[3])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(29);
    t[4] = x[1]
        .wrapping_add(x[2])
        .wrapping_add(x[3])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .rotate_left(31);
    t[5] = x[0]
        .wrapping_add(x[2])
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[5])
        .rotate_left(41);
    t[6] = x[0]
        .wrapping_add(x[1])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .wrapping_add(x[7])
        .rotate_left(57);
    t[7] = x[2]
        .wrapping_add(x[3])
        .wrapping_add(x[4])
        .wrapping_add(x[5])
        .wrapping_add(x[6])
        .rotate_left(61);
    t[8] = t[3] ^ t[5] ^ t[6];
    t[9] = t[2] ^ t[5] ^ t[6];
    t[10] = t[2] ^ t[3] ^ t[5];
    t[11] = t[0] ^ t[1] ^ t[4];
    t[12] = t[0] ^ t[4] ^ t[7];
    t[13] = t[1] ^ t[6] ^ t[7];
    t[14] = t[2] ^ t[3] ^ t[4];
    t[15] = t[0] ^ t[1] ^ t[7];
    // Second Orthogonal Latin Square
    t[0] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[2])
        .wrapping_add(y[5])
        .wrapping_add(y[7])
        .wrapping_add(0x5555_5555_5555_5555);
    t[1] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .rotate_left(3);
    t[2] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[2])
        .wrapping_add(y[3])
        .wrapping_add(y[5])
        .rotate_left(17);
    t[3] = y[2]
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(23);
    t[4] = y[0]
        .wrapping_add(y[1])
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[5])
        .rotate_left(31);
    t[5] = y[2]
        .wrapping_add(y[4])
        .wrapping_add(y[5])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(37);
    t[6] = y[1]
        .wrapping_add(y[2])
        .wrapping_add(y[5])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(45);
    t[7] = y[0]
        .wrapping_add(y[3])
        .wrapping_add(y[4])
        .wrapping_add(y[6])
        .wrapping_add(y[7])
        .rotate_left(59);
    z[5] = t[8].wrapping_add(t[3] ^ t[4] ^ t[6]);
    z[6] = t[9].wrapping_add(t[2] ^ t[5] ^ t[7]);
    z[7] = t[10].wrapping_add(t[4] ^ t[6] ^ t[7]);
    z[0] = t[11].wrapping_add(t[0] ^ t[1] ^ t[5]);
    z[1] = t[12].wrapping_add(t[2] ^ t[6] ^ t[7]);
    z[2] = t[13].wrapping_add(t[0] ^ t[1] ^ t[3]);
    z[3] = t[14].wrapping_add(t[0] ^ t[3] ^ t[4]);
    z[4] = t[15].wrapping_add(t[1] ^ t[2] ^ t[5]);
    z
}
