//! Blinded zero-knowledge proof of equality of discrete logarithms (aka protocol Γ)

use crate::{
    error::{Error, Result},
    hash::{TranscriptDigest as _, TranscriptProtocol as _},
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::Transcript;
use rand::thread_rng;

use super::{dlog_eq, LocalProofTransport};

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
pub async fn prove<T: LocalProofTransport>(
    t: &mut T,
    publics: Publics,
    secrets: ProverSecrets,
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
pub async fn verify<T: LocalProofTransport>(
    t: &mut T,
    publics: Publics,
    secrets: VerifierSecrets,
) -> Result<DlogEqTranscript, Error> {
    let a: RistrettoPoint = t.receive(b"a").await?;
    let b: RistrettoPoint = t.receive(b"b").await?;

    let α = Scalar::random(&mut thread_rng());
    let β = Scalar::random(&mut thread_rng());
    let a1 = a + α * publics.g + β * publics.h;
    let b1 = secrets.γ * (b + α * publics.g1 + β * publics.h1);
    let c_minus_β = hash(a1, b1);
    let c = c_minus_β + β;
    t.send(b"c", c).await?;
    let y: Scalar = t.receive(b"y").await?;

    let a_ok = y * publics.g == a + c * publics.h;
    let b_ok = y * publics.g1 == b + c * publics.h1;
    if a_ok & b_ok {
        Ok(DlogEqTranscript {
            a: a1,
            b: b1,
            c: c_minus_β,
            y: y + α,
        })
    } else {
        Err(Error::BadProof)
    }
}

/// A transcript of protocol Π_NI
pub struct DlogEqTranscript {
    a: RistrettoPoint,
    b: RistrettoPoint,
    c: Scalar,
    y: Scalar,
}

impl DlogEqTranscript {
    /// Verifies this transcript
    pub fn verify(&self, publics: Publics) -> Result {
        let a_ok = self.y * publics.g == self.a + self.c * publics.h;
        let b_ok = self.y * publics.g1 == self.b + self.c * publics.h1;
        if a_ok & b_ok {
            Ok(())
        } else {
            Err(Error::BadProof)
        }
    }
}

fn hash(a: RistrettoPoint, b: RistrettoPoint) -> Scalar {
    let mut h = Transcript::new(b"blind-dlog-eq-proof/non-interactive-challenge");
    h.append_value(b"a", &a);
    h.append_value(b"b", &b);
    Scalar::from_hash(h.into_digest())
}
