use ghash::{Hash, Sha256};

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
// SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
#[test]
fn sha256_1() {
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sha256 = Sha256::hash_to_lowercase("abc".as_bytes());
    assert_eq!(sha256, expected);
}

#[test]
fn sha256_2() {
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    let sha256 = Sha256::hash_to_lowercase(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
    );
    assert_eq!(sha256, expected);
}
