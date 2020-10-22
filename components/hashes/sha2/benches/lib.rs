#![feature(test)]

dev_utils::impl_benchmark!(sha2, Sha224);
dev_utils::impl_benchmark!(sha2, Sha256);
dev_utils::impl_benchmark!(sha2, Sha384);
dev_utils::impl_benchmark!(sha2, Sha512);
dev_utils::impl_benchmark!(sha2, Sha512Trunc224);
dev_utils::impl_benchmark!(sha2, Sha512Trunc256);
