#![allow(mixed_script_confusables, confusable_idents)]
#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! An implementation of a pseudonym system as described in https://www.princeton.edu/~rblee/ELE572Papers/Fall04Readings/lrsw.pdf

pub mod key;
pub mod nym;
pub mod error;

pub mod proof;
pub mod hash;
pub mod transport;
