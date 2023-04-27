#![no_std]

extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(feature = "minimal")]
mod minimal;

#[cfg(not(feature = "minimal"))]
pub use default::Md2;
#[cfg(feature = "minimal")]
pub use minimal::Md2;

#[cfg(test)]
mod tests {
    use super::Md2;
    use dev_util::impl_test;

    const OFFICIAL: [(&[u8], &str); 6] = [
        // https://tools.ietf.org/html/rfc1319
        ("".as_bytes(), "8350e5a3e24c153df2275c9f80692773"),
        ("a".as_bytes(), "32ec01ec4a6dac72c0ab96fb34c0b5d1"),
        (
            "message digest".as_bytes(),
            "ab4f496bfb2a530b219ff33031fe06b0",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            "4e8ddff3650292ab5a4108c3aa47940b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            "da33def2a42df13975352846c30338cd",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
            "d5976f79d83d3a0dc9806c3c66f3efd8",
        ),
    ];
    impl_test!(Md2, md2_official, OFFICIAL, Md2::default());
}
