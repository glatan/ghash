use sha0::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!("SHA-0:\t{:}", Sha0::default().hash_to_lowerhex(&input));
}