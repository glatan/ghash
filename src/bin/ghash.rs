use ghash::{Md2, Md4, Md5};
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end().as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("MD2: {:}", Md2::hash(&input));
    println!("MD4: {:}", Md4::hash(&input));
    println!("MD5: {:}", Md5::hash(&input));
}
