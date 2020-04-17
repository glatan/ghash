use ghash::{Hash, Sha512Trunc224};

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
// SHA512("abc") = 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9
#[test]
fn sha512trunc224_1() {
    let expected = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa";
    let sha512trunc224 = Sha512Trunc224::hash_to_lowercase("abc".as_bytes());
    assert_eq!(sha512trunc224, expected);
}

#[test]
fn sha512trunc224_2() {
    let expected = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9";
    let sha512trunc224 = Sha512Trunc224::hash_to_lowercase("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(sha512trunc224, expected);
}
