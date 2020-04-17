use ghash::Sha512Trunc256;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
// SHA512("abc") = 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a
#[test]
fn sha512trunc256_1() {
    let expected = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";
    let sha512trunc256 = Sha512Trunc256::hash("abc".as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    assert_eq!(sha512trunc256, expected);
}

#[test]
fn sha512trunc256_2() {
    let expected = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a";
    let sha512trunc256 = Sha512Trunc256::hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes()).iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    assert_eq!(sha512trunc256, expected);
}
