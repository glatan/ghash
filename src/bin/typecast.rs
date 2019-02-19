pub struct TypeCast {}

impl TypeCast {
    /*
    from_to
    ex: u8 ✕ 4 to u32 -> u8x4_u32
    */
    // LE
    pub fn u8x4_u32(b1: u8, b2: u8, b3: u8, b4: u8) -> u32 {
        let b1_u32: u32 = u32::from(b1);
        let b2_u32: u32 = u32::from(b2).rotate_left(8);
        let b3_u32: u32 = u32::from(b3).rotate_left(16);
        let b4_u32: u32 = u32::from(b4).rotate_left(24);
        // println!("{:x}, {:x}, {:x}, {:x}", b1_u32, b2_u32, b3_u32, b4_u32);
        b1_u32
            .wrapping_add(b2_u32)
            .wrapping_add(b3_u32)
            .wrapping_add(b4_u32)
    }
}
