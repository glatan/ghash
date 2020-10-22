#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(keccak, Keccak224);
impl_benchmark!(keccak, Keccak256);
impl_benchmark!(keccak, Keccak384);
impl_benchmark!(keccak, Keccak512);
