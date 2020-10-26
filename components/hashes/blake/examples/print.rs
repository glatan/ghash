use blake::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!("BLAKE-28\t{:}", Blake28::default().hash_to_lowerhex(&input));
    println!("BLAKE-32\t{:}", Blake32::default().hash_to_lowerhex(&input));
    println!("BLAKE-48\t{:}", Blake48::default().hash_to_lowerhex(&input));
    println!("BLAKE-64\t{:}", Blake64::default().hash_to_lowerhex(&input));
    println!(
        "BLAKE-224\t{:}",
        Blake224::default().hash_to_lowerhex(&input)
    );
    println!(
        "BLAKE-256\t{:}",
        Blake256::default().hash_to_lowerhex(&input)
    );
    println!(
        "BLAKE-384\t{:}",
        Blake384::default().hash_to_lowerhex(&input)
    );
    println!(
        "BLAKE-512\t{:}",
        Blake512::default().hash_to_lowerhex(&input)
    );
}
