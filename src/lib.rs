#![allow(mixed_script_confusables, confusable_idents)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

#![cfg_attr(test, feature(assert_matches))]

//! An implementation of a pseudonym system as described in <https://www.princeton.edu/~rblee/ELE572Papers/Fall04Readings/lrsw.pdf>

mod error;
pub use error::*;
mod key;
pub use key::*;
mod nym;
pub use nym::*;

mod hash;
mod proof;
mod transport;
