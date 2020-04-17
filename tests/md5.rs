use ghash::{Hash, Md5};

// https://tools.ietf.org/html/rfc1321
// A.5 Test suite
/*
MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a
*/

#[test]
fn md5_1() {
    let expected = "d41d8cd98f00b204e9800998ecf8427e";
    let md5 = Md5::hash_to_lowercase("".as_bytes());
    assert_eq!(md5, expected);
}

#[test]
fn md5_2() {
    let expected = "0cc175b9c0f1b6a831c399e269772661";
    let md5 = Md5::hash_to_lowercase("a".as_bytes());
    assert_eq!(md5, expected);
}

#[test]
fn md5_3() {
    let expected = "900150983cd24fb0d6963f7d28e17f72";
    let md5 = Md5::hash_to_lowercase("abc".as_bytes());
    assert_eq!(md5, expected);
}

#[test]
fn md5_4() {
    let expected = "f96b697d7cb7938d525a2f31aaf161d0";
    let md5 = Md5::hash_to_lowercase("message digest".as_bytes());
    assert_eq!(md5, expected);
}

#[test]
fn md5_5() {
    let expected = "c3fcd3d76192e4007dfb496cca67e13b";
    let md5 = Md5::hash_to_lowercase("abcdefghijklmnopqrstuvwxyz".as_bytes());
    assert_eq!(md5, expected);
}

#[test]
fn md5_6() {
    let expected = "d174ab98d277d9f5a5611c2c9f419d9f";
    let md5 = Md5::hash_to_lowercase(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
    );
    assert_eq!(md5, expected);
}

#[test]
fn md5_7() {
    let expected = "57edf4a22be3c955ac49da2e2107b67a";
    let md5 = Md5::hash_to_lowercase(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .as_bytes(),
    );
    assert_eq!(md5, expected);
}