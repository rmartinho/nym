//! Secret and public keys

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    proof::dlog_eq::{self, Publics, Secrets},
    transport::LocalTransport,
};

/// The secret part of a user's master key
#[derive(Serialize, Deserialize)]
pub struct UserSecretKey(Scalar);

/// The public part of a user's master key
#[derive(PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct UserPublicKey(RistrettoPoint);

/// The secret part of an organization's credential key
#[derive(Serialize, Deserialize)]
pub struct OrgSecretKey(Scalar, Scalar);

/// The public part of an organization's credential key
#[derive(PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct OrgPublicKey(RistrettoPoint, RistrettoPoint);

impl UserSecretKey {
    /// Generates a new random user secret key.
    pub fn random() -> Self {
        Self(Scalar::random(&mut thread_rng()))
    }

    /// Gets the public part of this key.
    pub fn public(&self) -> UserPublicKey {
        UserPublicKey(self.0 * RISTRETTO_BASEPOINT_POINT)
    }

    /// Gets this key's exponent
    pub(crate) fn exponent(&self) -> Scalar {
        self.0
    }
}

impl UserPublicKey {
    /// Gets this public key's point on the ristretto curve.
    pub fn point(&self) -> RistrettoPoint {
        self.0
    }
}

impl OrgSecretKey {
    /// Generates a new random organization secret key.
    pub fn random() -> Self {
        Self(
            Scalar::random(&mut thread_rng()),
            Scalar::random(&mut thread_rng()),
        )
    }

    /// Gets the public part of this key.
    pub fn public(&self) -> OrgPublicKey {
        OrgPublicKey(
            self.0 * RISTRETTO_BASEPOINT_POINT,
            self.1 * RISTRETTO_BASEPOINT_POINT,
        )
    }

    /// Gets this key's exponents
    pub(crate) fn exponents(&self) -> (Scalar, Scalar) {
        (self.0, self.1)
    }

    /// Proves ownership of this key to a user
    pub async fn prove_ownership<T: LocalTransport>(&self, user: &mut T) -> Result {
        prove_ownership(user, self.public().points().0, self.exponents().0).await?;
        prove_ownership(user, self.public().points().1, self.exponents().1).await
    }
}

impl OrgPublicKey {
    /// Gets this public key's points on the ristretto curve.
    pub fn points(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.0, self.1)
    }

    /// Verifies an organization's ownership of this key
    pub async fn verify_ownership<T: LocalTransport>(&self, org: &mut T) -> Result {
        verify_ownership(org, self.points().0).await?;
        verify_ownership(org, self.points().1).await
    }
}

/// Proves ownership of a public key
async fn prove_ownership<T: LocalTransport>(
    transport: &mut T,
    public: RistrettoPoint,
    secret: Scalar,
) -> Result {
    dlog_eq::prove(
        transport,
        Publics {
            g: RISTRETTO_BASEPOINT_POINT,
            h: public,
            g1: RISTRETTO_BASEPOINT_POINT,
            h1: public,
        },
        Secrets { x: secret },
    )
    .await
}

/// Verifies ownership of a public key
async fn verify_ownership<T: LocalTransport>(transport: &mut T, public: RistrettoPoint) -> Result {
    dlog_eq::verify(
        transport,
        Publics {
            g: RISTRETTO_BASEPOINT_POINT,
            h: public,
            g1: RISTRETTO_BASEPOINT_POINT,
            h1: public,
        },
    )
    .await
}
