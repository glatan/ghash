#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use sha3::Sha3_224, Sha3_224::default());
impl_benchmark!(use sha3::Sha3_256, Sha3_256::default());
impl_benchmark!(use sha3::Sha3_384, Sha3_384::default());
impl_benchmark!(use sha3::Sha3_512, Sha3_512::default());
impl_benchmark!(use sha3::Shake128, Shake128::default());
impl_benchmark!(use sha3::Shake256, Shake256::default());
