#![feature(test)]

use dev_util::impl_benchmark;

impl_benchmark!(sha2, Sha224);
impl_benchmark!(sha2, Sha256);
impl_benchmark!(sha2, Sha384);
impl_benchmark!(sha2, Sha512);
impl_benchmark!(sha2, Sha512Trunc224);
impl_benchmark!(sha2, Sha512Trunc256);
