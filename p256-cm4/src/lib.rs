#![no_std]
#![allow(clippy::missing_safety_doc)]

mod sys;
pub use sys::*;

use crate::asm::{Montgomery, P256_point_is_on_curve, P256_to_montgomery};

#[cfg(target_arch = "arm")]
pub(crate) mod asm;

/// A verifying key, also called a verifying key.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyingKey {
    x: [u32; 8],
    y: [u32; 8],
}

impl VerifyingKey {
    /// Create a new [`VerifyingKey`] from the provided raw, big-endian encoded
    /// `x` and `y` coordinates.
    ///
    /// An error is returned if `x` or `y` is not in the range `0..=p - 1`, where `p`
    /// is the `p256` prime, or if the point `(x, y)` is not on the `p256` curve.
    pub fn from_parts(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, ()> {
        let x = to_little_endian(x);
        let y = to_little_endian(y);

        if unsafe { !crate::asm::P256_check_range_p(&x) || !crate::asm::P256_check_range_p(&y) } {
            return Err(());
        }

        let mut x_mont = Montgomery::default();
        let mut y_mont = Montgomery::default();

        unsafe { P256_to_montgomery(&mut x_mont, &x) };
        unsafe { P256_to_montgomery(&mut y_mont, &y) };

        let valid = unsafe { P256_point_is_on_curve(&x_mont, &y_mont) };

        if valid { Ok(Self { x, y }) } else { Err(()) }
    }

    /// Verify that the private-key counterpart to this [`VerifyingKey`] has produced
    /// `signature` by signing `hash`.
    pub fn verify_prehash(&self, hash: &[u8; 32], signature: &Signature) -> bool {
        sys::verify_no_bounds_checks(&self.x, &self.y, hash, &signature.r, &signature.s)
    }
}

/// A signature.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    r: [u32; 8],
    s: [u32; 8],
}

impl Signature {
    /// Create a new [`Signature`] from the provided bytes.
    ///
    /// The first 32 bytes of the `bytes` are interpreted as the `r`
    /// value of this [`Signature`], and the second 32 bytes are interpreted
    /// as the `s` value. An error is returned if the two values don't
    /// constitute a valid [`Signature`] (see [`Signature::from_parts`] for
    /// more information on validity).
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, ()> {
        Self::from_parts(
            bytes[..32].try_into().unwrap(),
            bytes[32..].try_into().unwrap(),
        )
    }

    /// Create a new [`Signature`] from the little-endian encoded values
    /// `r` and `s`.
    ///
    /// An error is returned if `r` or `s` is not in the range `1..=n - 1`, where
    /// `n` is the `p256` order.
    pub fn from_parts(r: &[u8; 32], s: &[u8; 32]) -> Result<Self, ()> {
        let r = to_little_endian(r);
        let s = to_little_endian(s);

        if unsafe { !crate::asm::P256_check_range_n(&r) || !crate::asm::P256_check_range_n(&s) } {
            return Err(());
        }

        Ok(Self { r, s })
    }
}

/// Convert an input 256 bit number (big-endian u8s) into the format
/// used by this library (little-endian u32)
fn to_little_endian(input: &[u8; 32]) -> [u32; 8] {
    let mut output = [0u32; 8];

    // SAFETY: mutability & lifetime requirements are upheld
    let output_ref = transmute(&mut output);
    convert_endianness(output_ref, input);

    fn transmute<'a>(input: &'a mut [u32; 8]) -> &'a mut [u8; 32] {
        // SAFETY: we return a mutable reference with the same lifetime
        // as the input pointer. Additionally, all bit patterns for the
        // provided `[u32]` are valid for the returned `[u8]`, and the
        // alignment requirements for an `&mut [u8; 32]` are laxer than
        // those of a `&mut [u32; 8]`.
        unsafe { core::mem::transmute(input) }
    }

    output
}
