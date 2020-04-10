extern crate ghash;

use ghash::*;

// https://tools.ietf.org/html/rfc1319
// A.5 Test suite
/*
MD2 ("") = 8350e5a3e24c153df2275c9f80692773
MD2 ("a") = 32ec01ec4a6dac72c0ab96fb34c0b5d1
MD2 ("abc") = da853b0d3f88d99b30283a69e6ded6bb
MD2 ("message digest") = ab4f496bfb2a530b219ff33031fe06b0
MD2 ("abcdefghijklmnopqrstuvwxyz") = 4e8ddff3650292ab5a4108c3aa47940b
MD2 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = da33def2a42df13975352846c30338cd
MD2 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = d5976f79d83d3a0dc9806c3c66f3efd8
*/

#[test]
fn md2_1() {
    let expected = String::from("8350e5a3e24c153df2275c9f80692773");
    let md2 = Md2::hash("".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_2() {
    let expected = String::from("32ec01ec4a6dac72c0ab96fb34c0b5d1");
    let md2 = Md2::hash("a".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_3() {
    let expected = String::from("da853b0d3f88d99b30283a69e6ded6bb");
    let md2 = Md2::hash("abc".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_4() {
    let expected = String::from("ab4f496bfb2a530b219ff33031fe06b0");
    let md2 = Md2::hash("message digest".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_5() {
    let expected = String::from("4e8ddff3650292ab5a4108c3aa47940b");
    let md2 = Md2::hash("abcdefghijklmnopqrstuvwxyz".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_6() {
    let expected = String::from("da33def2a42df13975352846c30338cd");
    let md2 =
        Md2::hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes());
    assert_eq!(md2, expected);
}

#[test]
fn md2_7() {
    let expected = String::from("d5976f79d83d3a0dc9806c3c66f3efd8");
    let md2 = Md2::hash(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .as_bytes(),
    );
    assert_eq!(md2, expected);
}
