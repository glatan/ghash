#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(sha3, Sha3_224);
impl_benchmark!(sha3, Sha3_256);
impl_benchmark!(sha3, Sha3_384);
impl_benchmark!(sha3, Sha3_512);
impl_benchmark!(sha3, Shake128);
impl_benchmark!(sha3, Shake256);
