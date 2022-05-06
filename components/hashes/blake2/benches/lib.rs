#![feature(test)]

use dev_utils::impl_benchmark;

impl_benchmark!(use blake2::Blake2s, Blake2s::with_digest_len(32));
impl_benchmark!(use blake2::Blake2b, Blake2b::with_digest_len(64));
