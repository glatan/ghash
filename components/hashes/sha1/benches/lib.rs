#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use sha1::Sha1, Sha1::default());
