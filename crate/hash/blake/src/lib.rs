#![no_std]

extern crate alloc;

mod consts;
#[cfg(not(feature = "minimal"))]
mod default;
#[cfg(feature = "minimal")]
mod minimal;

#[cfg(not(feature = "minimal"))]
pub use default::{Blake224, Blake256, Blake28, Blake32, Blake384, Blake48, Blake512, Blake64};
#[cfg(feature = "minimal")]
pub use minimal::{Blake224, Blake256, Blake28, Blake32, Blake384, Blake48, Blake512, Blake64};
