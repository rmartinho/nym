//! Blinded zero-knowledge proof of equality of discrete logarithms (aka protocol Γ)

use crate::{
    error::{Error, Result},
    transport::LocalTransport,
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::thread_rng;

use super::dlog_eq::{self, Transcript};

/// Public parameters
pub type Publics = dlog_eq::Publics;

/// Secret parameters for the prover
pub type ProverSecrets = dlog_eq::Secrets;

/// Secret parameters for the verifier
#[derive(Copy, Clone)]
pub struct VerifierSecrets {
    /// Blinding factor
    pub γ: Scalar,
}

/// Performs the protocol for proving equality of discrete logarithms as the prover
pub async fn prove<T: LocalTransport>(
    t: &mut T,
    publics: Publics,
    secrets: ProverSecrets,
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
pub async fn verify<T: LocalTransport>(
    t: &mut T,
    publics: Publics,
    secrets: VerifierSecrets,
) -> Result<Transcript, Error> {
    let a: RistrettoPoint = t.receive(b"a").await?;
    let b: RistrettoPoint = t.receive(b"b").await?;

    let α = Scalar::random(&mut thread_rng());
    let β = Scalar::random(&mut thread_rng());
    let a1 = a + α * publics.g1 + β * publics.h1; // g*r + g*α * g*xβ = g*(r + α + xβ)
    let b1 = secrets.γ * (b + α * publics.g2 + β * publics.h2); // g*γr + g*γα * g*γxβ = g*γ*(r + α * xβ)
    let c_minus_β = dlog_eq::non_interactive_challenge_for(
        Publics {
            g2: secrets.γ * publics.g2,
            h2: secrets.γ * publics.h2,
            ..publics
        },
        a1,
        b1,
    ); // c
    let c = c_minus_β + β;
    t.send(b"c", c).await?;
    let y: Scalar = t.receive(b"y").await?; // r + (c+β)x + α = r + α + xβ + cx

    let a_ok = y * publics.g1 == a + c * publics.h1;
    let b_ok = y * publics.g2 == b + c * publics.h2;
    if a_ok & b_ok {
        Ok(Transcript {
            a: a1,
            b: b1,
            c: c_minus_β,
            y: y + α,
        })
    } else {
        Err(Error::BadProof)
    }
}
