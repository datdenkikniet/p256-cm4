#![no_std]
#![allow(clippy::missing_safety_doc)]

mod sys;
pub use sys::*;

#[cfg(target_arch = "arm")]
pub(crate) mod asm;
