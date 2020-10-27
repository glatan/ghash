#[macro_use]
extern crate clap;

use clap::{App, ArgMatches};
use ghash::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

macro_rules! impl_subcommands_matches {
    ($app:expr, $message:expr, $( $name:expr, $T:ident );+) => {
        match $app.subcommand() {
            $(
                ($name, Some(sub)) => {
                    $message = MessageFile::open(&sub);
                    print!("{}  ",$T::default().hash_to_lowerhex(&$message.message));
                },
            )+
            _ => panic!("Hash function must be selected")
        }
    };
}

struct MessageFile {
    name: String,
    message: Vec<u8>,
}

impl MessageFile {
    fn open(app: &ArgMatches) -> Self {
        let mut message = String::new();
        let filename;
        match app.value_of("file") {
            Some(path) => match File::open(path) {
                Ok(file) => {
                    match path.split("/").last() {
                        Some(name) => filename = name.to_owned(),
                        None => panic!("Failed to get file name.: {}", path),
                    }
                    let mut buf_reader = BufReader::new(file);
                    match buf_reader.read_to_string(&mut message) {
                        Ok(_) => (),
                        Err(e) => panic!(e),
                    }
                }
                Err(e) => panic!(e),
            },
            None => panic!("Missing file"),
        }
        Self {
            name: filename,
            message: message.as_bytes().to_owned(),
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml).get_matches();
    let message: MessageFile;

    impl_subcommands_matches!(app, message,
        "blake-224", Blake224;
        "blake-256", Blake256;
        "blake-384", Blake384;
        "blake-512", Blake512;
        "blake2s", Blake2s;
        "blake2b", Blake2b;
        "md2", Md2;
        "md4", Md4;
        "md5", Md5;
        "ripemd128", Ripemd128;
        "ripemd160", Ripemd160;
        "ripemd256", Ripemd256;
        "ripemd320", Ripemd320;
        "sha-0", Sha0;
        "sha-1", Sha1;
        "sha-224", Sha224;
        "sha-256", Sha256;
        "sha-384", Sha384;
        "sha-512", Sha512;
        "sha-512/224", Sha512Trunc224;
        "sha-512/256", Sha512Trunc256;
        "sha3-224", Sha3_224;
        "sha3-256", Sha3_256;
        "sha3-384", Sha3_384;
        "sha3-512", Sha3_512
    );
    println!("{}", message.name);
}
