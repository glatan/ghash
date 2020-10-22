#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(ripemd, Ripemd128);
impl_benchmark!(ripemd, Ripemd160);
impl_benchmark!(ripemd, Ripemd256);
impl_benchmark!(ripemd, Ripemd320);
