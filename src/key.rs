//! Secret and public keys

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey, SecretKey, PublicKey};

use crate::{
    error::Result,
    proof::dlog_eq::{self, Publics, Secrets},
    transport::LocalTransport,
};

/// The secret part of a user's master key
pub struct UserSecretKey {
    pub(crate) key: SecretKey,
}

/// The public part of a user's master key
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct UserPublicKey {
    key: PublicKey,
}

/// The secret part of an organization's credential key
pub struct OrgSecretKey {
    pub(crate) key1: SecretKey,
    pub(crate) key2: SecretKey,
}

/// The public part of an organization's credential key
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct OrgPublicKey {
    key1: PublicKey,
    key2: PublicKey,
}

impl UserSecretKey {
    /// Generates a new random user secret key.
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let seed = MiniSecretKey::generate_with(rng);
        Self {
            key: seed.expand(ExpansionMode::Uniform),
        }
    }

    /// Gets the public part of this key.
    pub fn to_public(&self) -> UserPublicKey {
        UserPublicKey {
            key: self.key.to_public()
        }
    }
}

impl UserPublicKey {
    /// Gets this public key's point on the ristretto curve.
    pub fn point(&self) -> RistrettoPoint {
        self.key.into_point()
    }
}

impl OrgSecretKey {
    /// Generates a new random organization secret key.
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let seed1 = MiniSecretKey::generate_with(&mut *rng);
        let seed2 = MiniSecretKey::generate_with(&mut *rng);
        Self {
            key1: seed1.expand(ExpansionMode::Uniform),
            key2: seed2.expand(ExpansionMode::Uniform),
        }
    }

    /// Gets the public part of this key.
    pub fn to_public(&self) -> OrgPublicKey {
        OrgPublicKey {
            key1: self.key1.to_public(),
            key2: self.key2.to_public(),
        }
    }

    /// Proves ownership of this key to a user
    pub async fn prove_ownership<T: LocalTransport>(&self, user: &mut T) -> Result {
        prove_ownership(user, self.to_public().key1.as_point(), self.key1.exponent()).await?;
        prove_ownership(user, self.to_public().key2.as_point(), self.key2.exponent()).await
    }
}

impl OrgPublicKey {
    /// Gets this public key's points on the ristretto curve.
    pub fn points(&self) -> (&RistrettoPoint, &RistrettoPoint) {
        (self.key1.as_point(), self.key2.as_point())
    }

    /// Verifies an organization's ownership of this key
    pub async fn verify_ownership<T: LocalTransport>(&self, org: &mut T) -> Result {
        verify_ownership(org, self.key1.as_point()).await?;
        verify_ownership(org, self.key2.as_point()).await
    }
}

/// Proves ownership of a public key
async fn prove_ownership<T: LocalTransport>(
    transport: &mut T,
    public: &RistrettoPoint,
    secret: &Scalar,
) -> Result {
    dlog_eq::prove(
        transport,
        Publics {
            g1: &RISTRETTO_BASEPOINT_POINT,
            h1: public,
            g2: &RISTRETTO_BASEPOINT_POINT,
            h2: public,
        },
        Secrets { x: secret },
    )
    .await
}

/// Verifies ownership of a public key
async fn verify_ownership<T: LocalTransport>(transport: &mut T, public: &RistrettoPoint) -> Result {
    dlog_eq::verify(
        transport,
        Publics {
            g1: &RISTRETTO_BASEPOINT_POINT,
            h1: public,
            g2: &RISTRETTO_BASEPOINT_POINT,
            h2: public,
        },
    )
    .await
}
