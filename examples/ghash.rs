use ghash::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("BLAKE-28\t{:}", Blake28::hash_to_lowerhex(&input));
    println!("BLAKE-32\t{:}", Blake32::hash_to_lowerhex(&input));
    println!("BLAKE-48\t{:}", Blake48::hash_to_lowerhex(&input));
    println!("BLAKE-64\t{:}", Blake64::hash_to_lowerhex(&input));
    println!("BLAKE-224\t{:}", Blake224::hash_to_lowerhex(&input));
    println!("BLAKE-256\t{:}", Blake256::hash_to_lowerhex(&input));
    println!("BLAKE-384\t{:}", Blake384::hash_to_lowerhex(&input));
    println!("BLAKE-512\t{:}", Blake512::hash_to_lowerhex(&input));
    println!("MD2:\t\t{:}", Md2::hash_to_lowerhex(&input));
    println!("MD4:\t\t{:}", Md4::hash_to_lowerhex(&input));
    println!("MD5:\t\t{:}", Md5::hash_to_lowerhex(&input));
    println!("RIPEMD-128:\t{:}", Ripemd128::hash_to_lowerhex(&input));
    println!("RIPEMD-160:\t{:}", Ripemd160::hash_to_lowerhex(&input));
    println!("RIPEMD-256:\t{:}", Ripemd256::hash_to_lowerhex(&input));
    println!("RIPEMD-320:\t{:}", Ripemd320::hash_to_lowerhex(&input));
    println!("SHA-0:\t\t{:}", Sha0::hash_to_lowerhex(&input));
    println!("SHA-1:\t\t{:}", Sha1::hash_to_lowerhex(&input));
    println!("SHA-224:\t{:}", Sha224::hash_to_lowerhex(&input));
    println!("SHA-256:\t{:}", Sha256::hash_to_lowerhex(&input));
    println!("SHA-384:\t{:}", Sha384::hash_to_lowerhex(&input));
    println!("SHA-512:\t{:}", Sha512::hash_to_lowerhex(&input));
    println!(
        "SHA-512/224:\t{:}",
        Sha512Trunc224::hash_to_lowerhex(&input)
    );
    println!(
        "SHA-512/256:\t{:}",
        Sha512Trunc256::hash_to_lowerhex(&input)
    );
}
