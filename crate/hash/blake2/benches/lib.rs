#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(blake2, Blake2s);
impl_benchmark!(blake2, Blake2b);
