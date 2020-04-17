use ghash::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end().as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("MD2:\t\t{:}", Md2::hash_to_lowercase(&input));
    println!("MD4:\t\t{:}", Md4::hash_to_lowercase(&input));
    println!("MD5:\t\t{:}", Md5::hash_to_lowercase(&input));
    println!("SHA0:\t\t{:}", Sha0::hash_to_lowercase(&input));
    println!("SHA1:\t\t{:}", Sha1::hash_to_lowercase(&input));
    println!("SHA224:\t\t{:}", Sha224::hash_to_lowercase(&input));
    println!("SHA256:\t\t{:}", Sha256::hash_to_lowercase(&input));
    println!("SHA384:\t\t{:}", Sha384::hash_to_lowercase(&input));
    println!("SHA512:\t\t{:}", Sha512::hash_to_lowercase(&input));
    println!(
        "SHA512/224:\t{:}",
        Sha512Trunc224::hash_to_lowercase(&input)
    );
    println!(
        "SHA512/256:\t{:}",
        Sha512Trunc256::hash_to_lowercase(&input)
    );
}
