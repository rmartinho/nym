//! Zero-knowledge proof of equality of discrete logarithms aka protocol Π

use crate::{
    error::{Error, Result},
    hash::TranscriptProtocol as _,
    transport::LocalTransport,
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

/// Public parameters
#[derive(Copy, Clone)]
pub struct Publics<'a> {
    /// First point's base
    pub g1: &'a RistrettoPoint,
    /// First point
    pub h1: &'a RistrettoPoint,
    /// Second point's base
    pub g2: &'a RistrettoPoint,
    /// Second point
    pub h2: &'a RistrettoPoint,
}

/// Secret parameters
#[derive(Copy, Clone)]
pub struct Secrets<'a> {
    /// Discrete logarithm
    pub x: &'a Scalar,
}

/// Performs the protocol for proving equality of discrete logarithms as the prover
pub async fn prove<T: LocalTransport>(
    t: &mut T,
    publics: Publics<'_>,
    secrets: Secrets<'_>,
) -> Result<(), Error> {
    let r = Scalar::random(&mut thread_rng());
    let a = r * publics.g1;
    let b = r * publics.g2;
    t.send(b"a", a).await?;
    t.send(b"b", b).await?;
    let c: Scalar = t.receive(b"c").await?;
    let y = r + c * secrets.x;
    t.send(b"y", y).await?;
    Ok(())
}

/// Performs the protocol for proving equality of discrete logarithms as the verifier
pub async fn verify<T: LocalTransport>(t: &mut T, publics: Publics<'_>) -> Result<(), Error> {
    let a: RistrettoPoint = t.receive(b"a").await?;
    let b: RistrettoPoint = t.receive(b"b").await?;
    let c = Scalar::random(&mut thread_rng());
    t.send(b"c", c).await?;
    let y: Scalar = t.receive(b"y").await?;
    let a_ok = y * publics.g1 == a + c * publics.h1;
    let b_ok = y * publics.g2 == b + c * publics.h2;
    if a_ok & b_ok {
        Ok(())
    } else {
        Err(Error::BadProof)
    }
}

/// A transcript of protocol Π_NI
#[derive(PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Transcript {
    pub a: RistrettoPoint,
    pub b: RistrettoPoint,
    pub c: Scalar,
    pub y: Scalar,
}

impl Transcript {
    /// Verifies this transcript
    pub fn verify(&self, publics: Publics) -> Result {
        let c_ok = self.c == non_interactive_challenge_for(publics, self.a, self.b);
        let a_ok = self.y * publics.g1 == self.a + self.c * publics.h1;
        let b_ok = self.y * publics.g2 == self.b + self.c * publics.h2;
        if c_ok && a_ok && b_ok {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }
}

/// Generates a non-interactive challenge for a proof of equality of discrete logarithms
pub fn non_interactive_challenge_for(
    publics: Publics,
    a: RistrettoPoint,
    b: RistrettoPoint,
) -> Scalar {
    let mut h = merlin::Transcript::new(b"nym/0.1/dlog-eq-proof/non-interactive-challenge");
    h.commit(b"g1", &publics.g1);
    h.commit(b"h1", &publics.h1);
    h.commit(b"g2", &publics.g2);
    h.commit(b"h2", &publics.h2);
    h.commit(b"a", &a);
    h.commit(b"b", &b);
    h.challenge(b"c")
}
