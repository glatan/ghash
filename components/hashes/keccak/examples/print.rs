use keccak::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!(
        "Keccak-224\t{:}",
        Keccak224::default().hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-256\t{:}",
        Keccak256::default().hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-384\t{:}",
        Keccak384::default().hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-512\t{:}",
        Keccak512::default().hash_to_lowerhex(&input)
    );
}
