#![feature(test)]

dev_utils::impl_benchmark!(blake, Blake28);
dev_utils::impl_benchmark!(blake, Blake32);
dev_utils::impl_benchmark!(blake, Blake48);
dev_utils::impl_benchmark!(blake, Blake64);
dev_utils::impl_benchmark!(blake, Blake224);
dev_utils::impl_benchmark!(blake, Blake256);
dev_utils::impl_benchmark!(blake, Blake384);
dev_utils::impl_benchmark!(blake, Blake512);
