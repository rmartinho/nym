//! Nym errors

use futures::io;

/// An error from this crate
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Verification of a proof failed
    #[error("proof verification failed")]
    BadProof,
    /// A transport error occurred
    #[error(transparent)]
    Transport(#[from] io::Error),
}

/// This crate's Result type
pub type Result<T = (), E = Error> = std::result::Result<T, E>;
