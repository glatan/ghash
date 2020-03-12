use ghash::{Md2Ctx, Md4Ctx, Md5Ctx};
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end().as_bytes().to_owned()
    };
    println!("input: {:?}", input);
    println!("MD2: {:}", Md2Ctx::hash(&input));
    println!("MD4: {:}", Md4Ctx::hash(&input));
    println!("MD5: {:}", Md5Ctx::hash(&input));
}
