use ghash::{Md2, Md4, Md5, Sha0, Sha1};
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end().as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("MD2:\t{:}", Md2::hash(&input));
    println!("MD4:\t{:}", Md4::hash(&input));
    println!("MD5:\t{:}", Md5::hash(&input));
    println!("SHA0:\t{:}", Sha0::hash(&input));
    println!("SHA1:\t{:}", Sha1::hash(&input));
}
