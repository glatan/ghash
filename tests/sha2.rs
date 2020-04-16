extern crate ghash;

use ghash::*;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
// SHA224 ("abc") = 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
// SHA224 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525
#[test]
fn sha224_1() {
    let expected = String::from("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    let sha224 = Sha224::hash("abc".as_bytes());
    assert_eq!(sha224, expected);
}

#[test]
fn sha224_2() {
    let expected = String::from("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    let sha224 =
        Sha224::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
    assert_eq!(sha224, expected);
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
// SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
#[test]
fn sha256_1() {
    let expected = String::from("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let sha256 = Sha256::hash("abc".as_bytes());
    assert_eq!(sha256, expected);
}

#[test]
fn sha256_2() {
    let expected = String::from("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    let sha256 =
        Sha256::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
    assert_eq!(sha256, expected);
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
// SHA384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
// SHA384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrl mnopqrsmnopqrstnopqrstu") = 09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039
#[test]
fn sha384_1() {
    let expected = String::from("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    let sha384 = Sha384::hash("abc".as_bytes());
    assert_eq!(sha384, expected);
}

#[test]
fn sha384_2() {
    let expected = String::from("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    let sha384 = Sha384::hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(sha384, expected);
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
// SHA512("abc") = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909
#[test]
fn sha512_1() {
    let expected = String::from("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    let sha512 = Sha512::hash("abc".as_bytes());
    assert_eq!(sha512, expected);
}

#[test]
fn sha512_2() {
    let expected = String::from("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    let sha512 = Sha512::hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(sha512, expected);
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
// SHA512("abc") = 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9
#[test]
fn sha512trunc224_1() {
    let expected = String::from("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    let sha512trunc224 = Sha512Trunc224::hash("abc".as_bytes());
    assert_eq!(sha512trunc224, expected);
}

#[test]
fn sha512trunc224_2() {
    let expected = String::from("23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
    let sha512trunc224 = Sha512Trunc224::hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(sha512trunc224, expected);
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
// SHA512("abc") = 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
// SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") = 3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a
#[test]
fn sha512trunc256_1() {
    let expected = String::from("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    let sha512trunc256 = Sha512Trunc256::hash("abc".as_bytes());
    assert_eq!(sha512trunc256, expected);
}

#[test]
fn sha512trunc256_2() {
    let expected = String::from("3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
    let sha512trunc256 = Sha512Trunc256::hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes());
    assert_eq!(sha512trunc256, expected);
}
