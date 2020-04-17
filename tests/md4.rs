use ghash::{Hash, Md4};

// https://tools.ietf.org/html/rfc1320
// A.5 Test suite
/*
MD4 ("") = 31d6cfe0d16ae931b73c59d7e0c089c0
MD4 ("a") = bde52cb31de33e46245e05fbdbd6fb24
MD4 ("abc") = a448017aaf21d8525fc10ae87aa6729d
MD4 ("message digest") = d9130a8164549fe818874806e1c7014b
MD4 ("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
MD4 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 043f8582f241db351ce627e153e7f0e4
MD4 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536
*/

#[test]
fn md4_1() {
    let expected = "31d6cfe0d16ae931b73c59d7e0c089c0";
    let md4 = Md4::hash_to_lowercase("".as_bytes());
    assert_eq!(md4, expected);
}

#[test]
fn md4_2() {
    let expected = "bde52cb31de33e46245e05fbdbd6fb24";
    let md4 = Md4::hash_to_lowercase("a".as_bytes());
    assert_eq!(md4, expected);
}

#[test]
fn md4_3() {
    let expected = "a448017aaf21d8525fc10ae87aa6729d";
    let md4 = Md4::hash_to_lowercase("abc".as_bytes());
    assert_eq!(md4, expected);
}

#[test]
fn md4_4() {
    let expected = "d9130a8164549fe818874806e1c7014b";
    let md4 = Md4::hash_to_lowercase("message digest".as_bytes());
    assert_eq!(md4, expected);
}

#[test]
fn md4_5() {
    let expected = "d79e1c308aa5bbcdeea8ed63df412da9";
    let md4 = Md4::hash_to_lowercase("abcdefghijklmnopqrstuvwxyz".as_bytes());
    assert_eq!(md4, expected);
}

#[test]
fn md4_6() {
    let expected = "043f8582f241db351ce627e153e7f0e4";
    let md4 = Md4::hash_to_lowercase(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
    );
    assert_eq!(md4, expected);
}

#[test]
fn md4_7() {
    let expected = "e33b4ddc9c38f2199c3e7b164fcc0536";
    let md4 = Md4::hash_to_lowercase(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .as_bytes(),
    );
    assert_eq!(md4, expected);
}
