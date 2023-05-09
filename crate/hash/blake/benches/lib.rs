#![feature(test)]

use dev_util::impl_benchmark;

impl_benchmark!(blake, Blake28);
impl_benchmark!(blake, Blake32);
impl_benchmark!(blake, Blake48);
impl_benchmark!(blake, Blake64);
impl_benchmark!(blake, Blake224);
impl_benchmark!(blake, Blake256);
impl_benchmark!(blake, Blake384);
impl_benchmark!(blake, Blake512);
