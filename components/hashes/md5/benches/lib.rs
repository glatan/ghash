#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use md5::Md5, Md5::default());
