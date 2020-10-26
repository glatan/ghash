use blake2::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!(
        "BLAKE2s-256\t{:}",
        Blake2s::default().hash_to_lowerhex(&input)
    );
    println!(
        "BLAKE2b-512\t{:}",
        Blake2b::default().hash_to_lowerhex(&input)
    );
}
