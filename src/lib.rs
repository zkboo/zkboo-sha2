// SPDX-License-Identifier: LGPL-3.0-or-later

//! SHA-2 primitives primitives for the [zkboo] crate.
//!
//! See <https://datatracker.ietf.org/doc/html/rfc6234> for details.

#![no_std]
extern crate alloc;

#[cfg(feature = "sha256")]
pub mod sha256;
#[cfg(feature = "sha512")]
pub mod sha512;

#[cfg(feature = "sha256")]
pub use sha256::{SHA256_BLOCKSIZE, sha224, sha224bytes, sha256, sha256bytes};
#[cfg(feature = "sha512")]
pub use sha512::{SHA512_BLOCKSIZE, sha384, sha384bytes, sha512, sha512bytes};
