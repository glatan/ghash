use sha2::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!("SHA-224:\t{:}", Sha224::default().hash_to_lowerhex(&input));
    println!("SHA-256:\t{:}", Sha256::default().hash_to_lowerhex(&input));
    println!("SHA-384:\t{:}", Sha384::default().hash_to_lowerhex(&input));
    println!("SHA-512:\t{:}", Sha512::default().hash_to_lowerhex(&input));
    println!(
        "SHA-512/224:\t{:}",
        Sha512Trunc224::default().hash_to_lowerhex(&input)
    );
    println!(
        "SHA-512/256:\t{:}",
        Sha512Trunc256::default().hash_to_lowerhex(&input)
    );
}
