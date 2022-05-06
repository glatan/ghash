#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use blake::Blake28, Blake28::default());
impl_benchmark!(use blake::Blake32, Blake32::default());
impl_benchmark!(use blake::Blake48, Blake48::default());
impl_benchmark!(use blake::Blake64, Blake64::default());
impl_benchmark!(use blake::Blake224, Blake224::default());
impl_benchmark!(use blake::Blake256, Blake256::default());
impl_benchmark!(use blake::Blake384, Blake384::default());
impl_benchmark!(use blake::Blake512, Blake512::default());
