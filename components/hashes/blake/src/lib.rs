mod consts;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::{Blake224, Blake256, Blake28, Blake32, Blake384, Blake48, Blake512, Blake64};

// #[cfg(feature = "default")]
// mod default;
// #[cfg(feature = "default")]
// pub use default::{Blake224, Blake256, Blake28, Blake32, Blake384, Blake48, Blake512, Blake64};
