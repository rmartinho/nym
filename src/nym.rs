//! Pseudo*nym* generation and verification

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::thread_rng;

use crate::{
    error::Result,
    key::{OrgPublicKey, OrgSecretKey, UserPublicKey, UserSecretKey},
    proof::{
        blind_dlog_eq::{self, DlogEqTranscript, ProverSecrets, VerifierSecrets},
        dlog_eq::{self, Publics},
    },
    transport::LocalTransport,
};

/// A pseudonym
pub struct Nym {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A credential
pub struct Cred {
    a: RistrettoPoint,
    b: RistrettoPoint,
    a1: RistrettoPoint,
    b1: RistrettoPoint,
    t1: DlogEqTranscript,
    t2: DlogEqTranscript,
}

/// An organization
pub struct Org {
    sk: OrgSecretKey,
    pk: OrgPublicKey,
}

/// A user
pub struct User {
    sk: UserSecretKey,
    _pk: UserPublicKey,
}

impl Org {
    /// Generates a pseudonym
    pub async fn generate_nym<T: LocalTransport>(&self, user: &mut T) -> Result<Nym> {
        let a1 = user.receive(b"a~").await?;
        let b1 = user.receive(b"b~").await?;
        let r = Scalar::random(&mut thread_rng());
        let a = r * a1;
        let b = user.receive(b"b").await?;

        user.send(b"a", a).await?;
        dlog_eq::verify(
            user,
            Publics {
                g: a,
                h: b,
                g1: a1,
                h1: b1,
            },
        )
        .await?;
        Ok(Nym { a, b })
    }
}

impl User {
    /// Generates a pseudonym
    pub async fn generate_nym<T: LocalTransport>(&self, org: &mut T) -> Result<Nym> {
        let γ = Scalar::random(&mut thread_rng());
        let a1 = γ * RISTRETTO_BASEPOINT_POINT;
        let b1 = self.sk.exponent() * a1;
        org.send(b"a~", a1).await?;
        org.send(b"b~", b1).await?;
        let a = org.receive(b"a").await?;
        let b = self.sk.exponent() * a;
        org.send(b"b", b);
        dlog_eq::prove(
            org,
            Publics {
                g: a,
                h: b,
                g1: a1,
                h1: b1,
            },
            ProverSecrets {
                x: self.sk.exponent(),
            },
        )
        .await?;
        Ok(Nym { a, b })
    }
}

impl Org {
    /// Authenticates a user as the holder of a given nym
    pub async fn authenticate_nym<T: LocalTransport>(&self, user: &mut T, nym: Nym) -> Result {
        dlog_eq::verify(
            user,
            Publics {
                g: nym.a,
                h: nym.b,
                g1: nym.a,
                h1: nym.b,
            },
        )
        .await?;
        Ok(())
    }
}

impl User {
    /// Authenticates this user as the holder of a given nym
    pub async fn authenticate_nym<T: LocalTransport>(&self, org: &mut T, nym: Nym) -> Result {
        dlog_eq::prove(
            org,
            Publics {
                g: nym.a,
                h: nym.b,
                g1: nym.a,
                h1: nym.b,
            },
            ProverSecrets {
                x: self.sk.exponent(),
            },
        )
        .await?;
        Ok(())
    }
}

impl Org {
    /// Issues a new credential for a given nym
    pub async fn issue_credential<T: LocalTransport>(&self, user: &mut T, nym: Nym) -> Result {
        let a1 = self.sk.exponents().1 * nym.b;
        let b1 = self.sk.exponents().0 * (nym.a + self.sk.exponents().1 * nym.b);
        user.send(b"A", a1).await?;
        user.send(b"B", b1).await?;

        blind_dlog_eq::prove(
            user,
            Publics {
                g: nym.b,
                h: a1,
                g1: RISTRETTO_BASEPOINT_POINT,
                h1: self.pk.points().1,
            },
            ProverSecrets {
                x: self.sk.exponents().1,
            },
        )
        .await?;
        blind_dlog_eq::prove(
            user,
            Publics {
                g: nym.a + a1,
                h: b1,
                g1: RISTRETTO_BASEPOINT_POINT,
                h1: self.pk.points().0,
            },
            ProverSecrets {
                x: self.sk.exponents().0,
            },
        )
        .await?;
        Ok(())
    }
}

impl User {
    /// Issues a new credential for a given nym
    pub async fn issue_credential<T: LocalTransport>(
        &self,
        org: &mut T,
        nym: Nym,
        source_key: OrgPublicKey,
    ) -> Result<Cred> {
        let a1 = org.receive(b"A").await?;
        let b1 = org.receive(b"B").await?;
        let γ = Scalar::random(&mut thread_rng());
        let t1 = blind_dlog_eq::verify(
            org,
            Publics {
                g: nym.b,
                h: a1,
                g1: RISTRETTO_BASEPOINT_POINT,
                h1: source_key.points().1,
            },
            VerifierSecrets { γ },
        )
        .await?;
        let t2 = blind_dlog_eq::verify(
            org,
            Publics {
                g: nym.a + a1,
                h: b1,
                g1: RISTRETTO_BASEPOINT_POINT,
                h1: source_key.points().0,
            },
            VerifierSecrets { γ },
        )
        .await?;
        Ok(Cred {
            a: nym.a * γ,
            b: nym.b * γ,
            a1: a1 * γ,
            b1: b1 * γ,
            t1,
            t2,
        })
    }
}

impl Org {
    /// Transfers a credential from one organization to another
    pub async fn transfer_credential<T: LocalTransport>(
        &self,
        user: &mut T,
        nym: Nym,
        cred: Cred,
    ) -> Result {
        cred.t1.verify(Publics {
            g: cred.b,
            h: cred.a1,
            g1: RISTRETTO_BASEPOINT_POINT,
            h1: self.pk.points().1,
        })?;
        cred.t2.verify(Publics {
            g: cred.a + cred.a1,
            h: cred.b1,
            g1: RISTRETTO_BASEPOINT_POINT,
            h1: self.pk.points().0,
        })?;
        dlog_eq::verify(
            user,
            Publics {
                g: nym.a,
                h: nym.b,
                g1: cred.a,
                h1: cred.b,
            },
        )
        .await?;
        Ok(())
    }
}

impl User {
    /// Transfers a credential from one organization to another
    pub async fn transfer_credential<T: LocalTransport>(
        &self,
        org: &mut T,
        nym: Nym,
        cred: Cred,
    ) -> Result {
        dlog_eq::prove(
            org,
            Publics {
                g: nym.a,
                h: nym.b,
                g1: cred.a,
                h1: cred.b,
            },
            ProverSecrets {
                x: self.sk.exponent(),
            },
        )
        .await?;
        Ok(())
    }
}
