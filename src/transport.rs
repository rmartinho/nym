//! Transport abstraction

use futures::io;
use serde::{Deserialize, Serialize};

/// A transport for protocols
#[trait_variant::make(Transport: Send)]
pub trait LocalTransport {
    /// Receives a value with a given label
    async fn receive<V: for<'a> Deserialize<'a>>(
        &mut self,
        label: &'static [u8],
    ) -> Result<V, io::Error>;

    /// Sends a value with a given label
    async fn send<V: Serialize>(&mut self, label: &'static [u8], value: V)
        -> Result<(), io::Error>;
}
