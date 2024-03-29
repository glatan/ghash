#![no_std]

extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(feature = "minimal")]
mod minimal;

#[cfg(not(feature = "minimal"))]
pub use default::Sha0;
#[cfg(feature = "minimal")]
pub use minimal::Sha0;

#[cfg(test)]
mod tests {
    use super::Sha0;
    use dev_util::impl_test;

    const OFFICIAL: [(&[u8], &str); 2] = [
        // https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
        // https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
        ("abc".as_bytes(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
        ),
    ];
    impl_test!(Sha0, official, OFFICIAL, Sha0::default());
}
