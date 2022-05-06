#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use edonr::EdonR224, EdonR224::default());
impl_benchmark!(use edonr::EdonR256, EdonR256::default());
impl_benchmark!(use edonr::EdonR384, EdonR384::default());
impl_benchmark!(use edonr::EdonR512, EdonR512::default());
