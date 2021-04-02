#![no_std]
extern crate alloc;

mod consts;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::{Blake2b, Blake2s};

#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(not(feature = "minimal"))]
pub use default::{Blake2b, Blake2s};
