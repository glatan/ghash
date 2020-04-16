extern crate ghash;

use ghash::*;

// https://tools.ietf.org/html/rfc3174
/*
SHA1 ("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
SHA1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
SHA1 ("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
SHA1 ("0123456701234567012345670123456701234567012345670123456701234567") = e0c094e867ef46c350ef54a7f59dd60bed92ae83
*/

#[test]
fn sha1_1() {
    let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
    let sha1 = Sha1::hash("abc".as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    assert_eq!(sha1, expected);
}

#[test]
fn sha1_2() {
    let expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
    let sha1 = Sha1::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    assert_eq!(sha1, expected);
}

#[test]
fn sha1_3() {
    let expected = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8";
    let sha1 = Sha1::hash("a".as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    assert_eq!(sha1, expected);
}

#[test]
fn sha1_4() {
    let expected = "e0c094e867ef46c350ef54a7f59dd60bed92ae83";
    let sha1 =
        Sha1::hash("0123456701234567012345670123456701234567012345670123456701234567".as_bytes())
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
    assert_eq!(sha1, expected);
}
