#![no_std]

extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod default;
mod macros;
#[cfg(feature = "minimal")]
mod minimal;

#[cfg(not(feature = "minimal"))]
pub use default::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
#[cfg(feature = "minimal")]
pub use minimal::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
