use ghash::*;
use std::io;
use std::io::BufRead;

fn main() {
    let input: Vec<u8> = {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).unwrap();
        input.trim_end_matches('\n').as_bytes().to_owned()
    };
    println!("input: {:?}", input);
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
    println!(
        "BLAKE2s-256\t{:}",
        Blake2s::default().hash_to_lowerhex(&input)
    );
    println!(
        "BLAKE2b-512\t{:}",
        Blake2b::default().hash_to_lowerhex(&input)
    );
    println!(
        "EDON-R224\t{:}",
        EdonR224::default().hash_to_lowerhex(&input)
    );
    println!(
        "EDON-R256\t{:}",
        EdonR256::default().hash_to_lowerhex(&input)
    );
    println!(
        "EDON-R384\t{:}",
        EdonR384::default().hash_to_lowerhex(&input)
    );
    println!(
        "EDON-R512\t{:}",
        EdonR512::default().hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[200](r=40, c=160):\t{:}",
        KeccakF200::new(40, 160, 64).hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[400](r=144, c=256):\t{:}",
        KeccakF400::new(144, 256, 64).hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[400](r=240, c=160):\t{:}",
        KeccakF400::new(240, 160, 64).hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[800](r=288, c=512):\t{:}",
        KeccakF800::new(288, 512, 64).hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[800](r=544, c=256):\t{:}",
        KeccakF800::new(544, 256, 64).hash_to_lowerhex(&input)
    );
    println!(
        "Keccak-f[800](r=640, c=160):\t{:}",
        KeccakF800::new(640, 160, 64).hash_to_lowerhex(&input)
    );
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
    println!("MD2:\t\t{:}", Md2::default().hash_to_lowerhex(&input));
    println!("MD4:\t\t{:}", Md4::default().hash_to_lowerhex(&input));
    println!("MD5:\t\t{:}", Md5::default().hash_to_lowerhex(&input));
    println!(
        "RIPEMD-128:\t{:}",
        Ripemd128::default().hash_to_lowerhex(&input)
    );
    println!(
        "RIPEMD-160:\t{:}",
        Ripemd160::default().hash_to_lowerhex(&input)
    );
    println!(
        "RIPEMD-256:\t{:}",
        Ripemd256::default().hash_to_lowerhex(&input)
    );
    println!(
        "RIPEMD-320:\t{:}",
        Ripemd320::default().hash_to_lowerhex(&input)
    );
    println!("SHA-0:\t\t{:}", Sha0::default().hash_to_lowerhex(&input));
    println!("SHA-1:\t\t{:}", Sha1::default().hash_to_lowerhex(&input));
    println!("SHA-224:\t{:}", Sha224::default().hash_to_lowerhex(&input));
    println!("SHA-256:\t{:}", Sha256::default().hash_to_lowerhex(&input));
    println!("SHA-384:\t{:}", Sha384::default().hash_to_lowerhex(&input));
    println!("SHA-512:\t{:}", Sha512::default().hash_to_lowerhex(&input));
    println!(
        "SHA-512/224:\t{:}",
        Sha512Trunc224::default().hash_to_lowerhex(&input)
    );
    println!(
        "SHA-512/256:\t{:}",
        Sha512Trunc256::default().hash_to_lowerhex(&input)
    );
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
