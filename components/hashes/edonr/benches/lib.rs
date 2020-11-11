#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(edonr, EdonR224);
impl_benchmark!(edonr, EdonR256);
impl_benchmark!(edonr, EdonR384);
impl_benchmark!(edonr, EdonR512);
