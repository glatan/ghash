use ghash::hash;
use std::io;
use std::io::BufRead;

fn main() {
    let input_data = {
        let mut input_data = String::new();
        io::stdin().lock().read_line(&mut input_data).unwrap();
        input_data.trim_end().as_bytes().to_vec()
    };
    println!("input_data: {:?}", input_data);
    hash::Md2Ctx::new(input_data).padding().add_check_sum().round().print_hash();
}
