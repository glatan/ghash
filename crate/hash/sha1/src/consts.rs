pub(crate) const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

pub(crate) const IV: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

#[inline(always)]
pub(crate) const fn ch(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}
#[inline(always)]
pub(crate) const fn parity(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
#[inline(always)]
pub(crate) const fn maj(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}
