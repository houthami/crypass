//! OS-specific behaviour lives behind this module so a Linux backend can be
//! added later without changing the rest of the app.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use self::unsupported::*;
