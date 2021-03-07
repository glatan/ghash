// Reference
// https://keccak.team/files/Keccak-reference-3.0.pdf

// Keccak-f[b]
// b = r + c
// b ∈ {25,50,100,200,400,800,1600}
// w ∈ {1,2,4,8,16,32,64}

// SHA-3 Submission
// https://keccak.team/files/Keccak-submission-3.pdf
// Keccak-224: [r=1152, c=448]
// Keccak-256: [r=1088, c=512]
// Keccak-384: [r=832, c=768]
// Keccak-512: [r=576, c=1024]

#![no_std]
#[macro_use]
extern crate alloc;

mod consts;
mod keccak_f1600;

mod keccak224;
mod keccak256;
mod keccak384;
mod keccak512;

pub use keccak_f1600::KeccakF1600;

pub use keccak224::Keccak224;
pub use keccak256::Keccak256;
pub use keccak384::Keccak384;
pub use keccak512::Keccak512;

struct Keccak<T> {
    state: [[T; 5]; 5], // A, S
    l: usize,
    n: usize,
    r: usize, // bitrate
    w: usize, // lane size
}
