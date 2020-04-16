use ghash::*;
use std::io;
use std::io::BufRead;

fn vec_to_string(vec: Vec<u8>) -> String {
    vec.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end().as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("MD2:\t\t{:}", vec_to_string(Md2::hash(&input)));
    println!("MD4:\t\t{:}", vec_to_string(Md4::hash(&input)));
    println!("MD5:\t\t{:}", vec_to_string(Md5::hash(&input)));
    println!("SHA0:\t\t{:}", vec_to_string(Sha0::hash(&input)));
    println!("SHA1:\t\t{:}", vec_to_string(Sha1::hash(&input)));
    println!("SHA224:\t\t{:}", vec_to_string(Sha224::hash(&input)));
    println!("SHA256:\t\t{:}", vec_to_string(Sha256::hash(&input)));
    println!("SHA384:\t\t{:}", vec_to_string(Sha384::hash(&input)));
    println!("SHA512:\t\t{:}", vec_to_string(Sha512::hash(&input)));
    println!(
        "SHA512/224:\t{:}",
        vec_to_string(Sha512Trunc224::hash(&input))
    );
    println!(
        "SHA512/256:\t{:}",
        vec_to_string(Sha512Trunc256::hash(&input))
    );
}
