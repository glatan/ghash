// Reference
// https://www.schneier.com/academic/paperfiles/skein1.3.pdf

use super::{Hash, Message};

struct Skein {
    message: Vec<u8>,
    word: Vec<u64>,
}

impl Skein {
    fn padding(&mut self) {}
}
