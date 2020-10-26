use sha3::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!(
        "SHA3-224:\t{:}",
        Sha3_224::default().hash_to_lowerhex(&input)
    );
    println!(
        "SHA3-256:\t{:}",
        Sha3_256::default().hash_to_lowerhex(&input)
    );
    println!(
        "SHA3-384:\t{:}",
        Sha3_384::default().hash_to_lowerhex(&input)
    );
    println!(
        "SHA3-512:\t{:}",
        Sha3_512::default().hash_to_lowerhex(&input)
    );
}
