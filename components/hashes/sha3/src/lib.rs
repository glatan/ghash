// https://keccak.team/keccak_specs_summary.html
// SHA3-224: [r=1152, c=448, d(suffix)=0x06]
// SHA3-256: [r=1088, c=512, d(suffix)=0x06]
// SHA3-384: [r=832, c=768, d(suffix)=0x06]
// SHA3-512: [r=576, c=1024, d(suffix)=0x06]

#![no_std]
extern crate alloc;

mod sha3_224;
mod sha3_256;
mod sha3_384;
mod sha3_512;
mod shake128;
mod shake256;

pub use utils::Hash;

pub use sha3_224::Sha3_224;
pub use sha3_256::Sha3_256;
pub use sha3_384::Sha3_384;
pub use sha3_512::Sha3_512;
pub use shake128::Shake128;
pub use shake256::Shake256;
