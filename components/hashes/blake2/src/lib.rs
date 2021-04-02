#![no_std]

extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(feature = "minimal")]
mod minimal;

#[cfg(not(feature = "minimal"))]
pub use default::{Blake2b, Blake2s};
#[cfg(feature = "minimal")]
pub use minimal::{Blake2b, Blake2s};
