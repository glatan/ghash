#![no_std]
extern crate alloc;

mod consts;
mod macros;

pub use utils::Hash;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};

#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(not(feature = "minimal"))]
pub use default::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
