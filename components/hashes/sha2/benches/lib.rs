#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use sha2::Sha224, Sha224::default());
impl_benchmark!(use sha2::Sha256, Sha256::default());
impl_benchmark!(use sha2::Sha384, Sha384::default());
impl_benchmark!(use sha2::Sha512, Sha512::default());
impl_benchmark!(use sha2::Sha512Trunc224, Sha512Trunc224::default());
impl_benchmark!(use sha2::Sha512Trunc256, Sha512Trunc256::default());
