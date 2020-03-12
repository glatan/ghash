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
    let md2_result: String = Md2Ctx::hash(&input);
    let md4_result: String = Md4Ctx::hash(&input);
    let md5_result: String = Md5Ctx::hash(&input);

    println!("MD2: {:}", md2_result);
    println!("MD4: {:}", md4_result);
    println!("MD5: {:}", md5_result);
}
