use ghash::{Hash, Sha0};

// https://web.archive.org/web/20180905102133/https://www-ljk.imag.fr/membres/Pierre.Karpman/fips180.pdf
// https://crypto.stackexchange.com/questions/62055/where-can-i-find-a-description-of-the-sha-0-hash-algorithm/62071#62071
/*
SHA0 ("abc") = 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
SHA0 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = d2516ee1acfa5baf33dfc1c471e438449ef134c8
*/

#[test]
fn sha0_1() {
    let expected = "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880";
    let sha0 = Sha0::hash_to_lowercase("abc".as_bytes());

    assert_eq!(sha0, expected);
}

#[test]
fn sha0_2() {
    let expected = "d2516ee1acfa5baf33dfc1c471e438449ef134c8";
    let sha0 = Sha0::hash_to_lowercase(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
    );

    assert_eq!(sha0, expected);
}
