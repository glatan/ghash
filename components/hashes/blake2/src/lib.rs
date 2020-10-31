mod consts;

pub use utils::Hash;

#[cfg(feature = "minimal")]
mod minimal;
#[cfg(feature = "minimal")]
pub use minimal::{Blake2b, Blake2s};

// #[cfg(not(feature = "minimal"))]
// mod default;
// #[cfg(not(feature = "minimal"))]
// pub use default::{Blake2s, Blake2b};
