#![no_std]
extern crate alloc;

mod consts;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::Sha1;

#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(not(feature = "minimal"))]
pub use default::Sha1;

#[cfg(test)]
mod tests {
    use super::Sha1;
    use dev_utils::impl_test;

    const OFFICIAL: [(&[u8], &str); 4] = [
        // https://tools.ietf.org/html/rfc3174
        ("abc".as_bytes(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        ("a".as_bytes(), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
        (
            "0123456701234567012345670123456701234567012345670123456701234567".as_bytes(),
            "e0c094e867ef46c350ef54a7f59dd60bed92ae83",
        ),
    ];
    impl_test!(Sha1, official, OFFICIAL, Sha1::default());
}
