//! Zero-knowledge proof of equality of discrete logarithms aka protocol Π

use crate::error::{Error, Result};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::thread_rng;

use super::LocalProofTransport;

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics {
    /// First point's base
    pub g: RistrettoPoint,
    /// First point
    pub h: RistrettoPoint,
    /// Second point's base
    pub g1: RistrettoPoint,
    /// Second point
    pub h1: RistrettoPoint,
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets {
    /// Discrete logarithm
    pub x: Scalar,
}

/// Performs the protocol for proving equality of discrete logarithms as the prover
pub async fn prove<T: LocalProofTransport>(
    t: &mut T,
    publics: Publics,
    secrets: Secrets,
) -> Result<(), Error> {
    let r = Scalar::random(&mut thread_rng());
    let a = r * publics.g;
    let b = r * publics.h;
    t.send(b"a", a).await?;
    t.send(b"b", b).await?;
    let c: Scalar = t.receive(b"c").await?;
    let y = r + c * secrets.x;
    t.send(b"y", y).await?;
    Ok(())
}

/// Performs the protocol for proving equality of discrete logarithms as the verifier
pub async fn verify<T: LocalProofTransport>(t: &mut T, publics: Publics) -> Result<(), Error> {
    let a: RistrettoPoint = t.receive(b"a").await?;
    let b: RistrettoPoint = t.receive(b"b").await?;
    let c = Scalar::random(&mut thread_rng());
    t.send(b"c", c).await?;
    let y: Scalar = t.receive(b"y").await?;
    let a_ok = y * publics.g == a + c * publics.h;
    let b_ok = y * publics.g1 == b + c * publics.h1;
    if a_ok & b_ok {
        Ok(())
    } else {
        Err(Error::BadProof)
    }
}
