#![feature(test)]

dev_utils::impl_benchmark!(keccak, Keccak224);
dev_utils::impl_benchmark!(keccak, Keccak256);
dev_utils::impl_benchmark!(keccak, Keccak384);
dev_utils::impl_benchmark!(keccak, Keccak512);
