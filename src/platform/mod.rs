//! Platform-gated path constants and OS shims.

pub mod signals;
pub mod unix;
pub use unix::*;
