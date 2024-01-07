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
pub async fn prove<T: LocalTransport>(
    t: &mut T,
    publics: Publics,
    secrets: Secrets,
) -> Result<(), Error> {
    let r = Scalar::random(&mut thread_rng());
    let a = r * publics.g;
    let b = r * publics.g1;
    t.send(b"a", a).await?;
    t.send(b"b", b).await?;
    let c: Scalar = t.receive(b"c").await?;
    let y = r + c * secrets.x;
    t.send(b"y", y).await?;
    Ok(())
}

/// Performs the protocol for proving equality of discrete logarithms as the verifier
pub async fn verify<T: LocalTransport>(t: &mut T, publics: Publics) -> Result<(), Error> {
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
        let a_ok = self.y * publics.g == self.a + self.c * publics.h;
        let b_ok = self.y * publics.g1 == self.b + self.c * publics.h1;
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
    h.append_value(b"g", &publics.g);
    h.append_value(b"h", &publics.h);
    h.append_value(b"g~", &publics.g1);
    h.append_value(b"h~", &publics.h1);
    h.append_value(b"a", &a);
    h.append_value(b"b", &b);
    let mut bytes = [0; 32];
    h.challenge_bytes(b"c", &mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
