//! Zero-knowledge proofs used in nyms

use futures::io;
use serde::{Deserialize, Serialize};

pub mod blind_dlog_eq;
pub mod dlog_eq;

/// A transport for proof data
#[trait_variant::make(ProofTransport: Send)]
pub trait LocalProofTransport {
    /// Receives a value with a given label
    async fn receive<V: for<'a> Deserialize<'a>>(
        &mut self,
        label: &'static [u8],
    ) -> Result<V, io::Error>;

    /// Sends a value with a given label
    async fn send<V: Serialize>(&mut self, label: &'static [u8], value: V)
        -> Result<(), io::Error>;
}
