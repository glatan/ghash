#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use keccak::Keccak224, Keccak224::default());
impl_benchmark!(use keccak::Keccak256, Keccak256::default());
impl_benchmark!(use keccak::Keccak384, Keccak384::default());
impl_benchmark!(use keccak::Keccak512, Keccak512::default());
