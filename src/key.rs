//! Secret and public keys

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::thread_rng;

/// The secret part of a user's master key
pub struct UserSecretKey(Scalar);

#[derive(Copy, Clone)]
/// The public part of a user's master key
pub struct UserPublicKey(RistrettoPoint);

/// The secret part of an organization's credential key
pub struct OrgSecretKey(Scalar, Scalar);

#[derive(Copy, Clone)]
/// The public part of an organization's credential key
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
}

impl OrgPublicKey {
    /// Gets this public key's points on the ristretto curve.
    pub fn points(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.0, self.1)
    }
}
