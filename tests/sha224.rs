use ghash::Sha224;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
// SHA224 ("abc") = 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
// SHA224 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525
#[test]
fn sha224_1() {
    let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    let sha224 = Sha224::hash("abc".as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    assert_eq!(sha224, expected);
}

#[test]
fn sha224_2() {
    let expected = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";
    let sha224 =
        Sha224::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes())
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
    assert_eq!(sha224, expected);
}
