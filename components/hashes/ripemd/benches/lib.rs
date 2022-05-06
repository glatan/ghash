#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use ripemd::Ripemd128, Ripemd128::default());
impl_benchmark!(use ripemd::Ripemd160, Ripemd160::default());
impl_benchmark!(use ripemd::Ripemd256, Ripemd256::default());
impl_benchmark!(use ripemd::Ripemd320, Ripemd320::default());
