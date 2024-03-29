//! Pseudo*nym* generation and verification

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::thread_rng;
use schnorrkel::{points::RistrettoBoth, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    key::{OrgPublicKey, OrgSecretKey, UserPublicKey, UserSecretKey},
    proof::{
        blind_dlog_eq::{self, ProverSecrets, VerifierSecrets},
        dlog_eq::{self, Publics, Transcript},
    },
    transport::LocalTransport,
};

/// A pseudonym
#[derive(PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Nym {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A credential
#[derive(PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Cred {
    a: RistrettoPoint,
    b: RistrettoPoint,
    A: RistrettoPoint,
    B: RistrettoPoint,
    T1: Transcript,
    T2: Transcript,
}

/// An organization
pub struct Org {
    sk: OrgSecretKey,
    pk: OrgPublicKey,
}

/// A user
pub struct User {
    sk: UserSecretKey,
    pk: UserPublicKey,
}

/// A nym-based signature
pub use schnorrkel::Signature;

impl UserSecretKey {
    /// Signs a transcript with a nym generated with this key
    #[allow(non_snake_case)]
    pub fn sign(&self, t: merlin::Transcript, nym: &Nym) -> Signature {
        self.key
            .sign_with_base(t, &RistrettoBoth::from_point(nym.b), &nym.a)
    }
}

impl Nym {
    /// Verifies a transcript signed with this nym
    #[allow(non_snake_case)]
    pub fn verify(&self, t: merlin::Transcript, sig: &Signature) -> Result {
        PublicKey::from_point(self.b)
            .verify_with_base(t, sig, &self.a)
            .map_err(|_| Error::BadSignature)
    }
}

impl Org {
    /// Initializes a new organization with the given secret key
    pub fn new(sk: OrgSecretKey) -> Self {
        Self {
            pk: sk.to_public(),
            sk,
        }
    }

    /// Gets this organization's public key
    pub fn public_key(&self) -> OrgPublicKey {
        self.pk
    }
}

impl User {
    /// Initializes a new user with the given secret key
    pub fn new(sk: UserSecretKey) -> Self {
        Self {
            pk: sk.to_public(),
            sk,
        }
    }

    /// Gets this user's public key
    pub fn public_key(&self) -> UserPublicKey {
        self.pk
    }
}

impl Org {
    /// Generates a pseudonym
    pub async fn generate_nym<T: LocalTransport>(&self, user: &mut T) -> Result<Nym> {
        let a_ = user.receive(b"a~").await?;
        let b_ = user.receive(b"b~").await?;
        let r = Scalar::random(&mut thread_rng());
        let a = r * a_;
        user.send(b"a", a).await?;
        let b: RistrettoPoint = user.receive(b"b").await?;
        dlog_eq::verify(
            user,
            Publics {
                g1: &a,
                h1: &b,
                g2: &a_,
                h2: &b_,
            },
        )
        .await?;
        Ok(Nym { a, b })
    }

    /// Generates a pseudonym as the CA
    pub async fn generate_nym_as_ca<T: LocalTransport>(
        &self,
        user: &mut T,
        user_key: UserPublicKey,
    ) -> Result<Nym> {
        let a_ = user.receive(b"a~").await?;
        let b_ = user.receive(b"b~").await?;
        if a_ != RISTRETTO_BASEPOINT_POINT {
            return Err(Error::BadProof);
        }
        if b_ != user_key.point() {
            return Err(Error::BadProof);
        }
        let r = Scalar::random(&mut thread_rng());
        let a = r * a_;
        user.send(b"a", a).await?;
        let b: RistrettoPoint = user.receive(b"b").await?;
        dlog_eq::verify(
            user,
            Publics {
                g1: &a,
                h1: &b,
                g2: &a_,
                h2: &b_,
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
        let a_ = γ * RISTRETTO_BASEPOINT_POINT;
        let b_ = self.sk.key.exponent() * a_;
        self.generate_nym_impl(org, a_, b_).await
    }

    /// Generates a pseudonym with a CA
    pub async fn generate_nym_with_ca<T: LocalTransport>(&self, org: &mut T) -> Result<Nym> {
        let a_ = RISTRETTO_BASEPOINT_POINT;
        let b_ = self.pk.point();
        self.generate_nym_impl(org, a_, b_).await
    }

    async fn generate_nym_impl<T: LocalTransport>(
        &self,
        org: &mut T,
        a_: RistrettoPoint,
        b_: RistrettoPoint,
    ) -> Result<Nym> {
        org.send(b"a~", a_).await?;
        org.send(b"b~", b_).await?;
        let a = org.receive(b"a").await?;
        let b = self.sk.key.exponent() * a;
        org.send(b"b", b).await?;
        dlog_eq::prove(
            org,
            Publics {
                g1: &a,
                h1: &b,
                g2: &a_,
                h2: &b_,
            },
            ProverSecrets {
                x: self.sk.key.exponent(),
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
                g1: &nym.a,
                h1: &nym.b,
                g2: &nym.a,
                h2: &nym.b,
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
                g1: &nym.a,
                h1: &nym.b,
                g2: &nym.a,
                h2: &nym.b,
            },
            ProverSecrets {
                x: self.sk.key.exponent(),
            },
        )
        .await?;
        Ok(())
    }
}

impl Org {
    /// Issues a new credential for a given nym
    #[allow(non_snake_case)]
    pub async fn issue_credential<T: LocalTransport>(&self, user: &mut T, nym: Nym) -> Result {
        let A = self.sk.key2.exponent() * nym.b;
        let B = self.sk.key1.exponent() * (nym.a + self.sk.key2.exponent() * nym.b);
        user.send(b"A", A).await?;
        user.send(b"B", B).await?;

        blind_dlog_eq::prove(
            user,
            Publics {
                g1: &RISTRETTO_BASEPOINT_POINT,
                h1: self.pk.points().1,
                g2: &nym.b,
                h2: &A,
            },
            ProverSecrets {
                x: self.sk.key2.exponent(),
            },
        )
        .await?;
        blind_dlog_eq::prove(
            user,
            Publics {
                g1: &RISTRETTO_BASEPOINT_POINT,
                h1: self.pk.points().0,
                g2: &(nym.a + A),
                h2: &B,
            },
            ProverSecrets {
                x: self.sk.key1.exponent(),
            },
        )
        .await?;
        Ok(())
    }
}

impl User {
    /// Issues a new credential for a given nym
    #[allow(non_snake_case)]
    pub async fn issue_credential<T: LocalTransport>(
        &self,
        org: &mut T,
        nym: Nym,
        source_key: OrgPublicKey,
    ) -> Result<Cred> {
        let A = org.receive(b"A").await?;
        let B = org.receive(b"B").await?;
        let γ = &Scalar::random(&mut thread_rng());
        let T1 = blind_dlog_eq::verify(
            org,
            Publics {
                g1: &RISTRETTO_BASEPOINT_POINT,
                h1: source_key.points().1,
                g2: &nym.b,
                h2: &A,
            },
            VerifierSecrets { γ },
        )
        .await?;
        let T2 = blind_dlog_eq::verify(
            org,
            Publics {
                g1: &RISTRETTO_BASEPOINT_POINT,
                h1: source_key.points().0,
                g2: &(nym.a + A),
                h2: &B,
            },
            VerifierSecrets { γ },
        )
        .await?;
        Ok(Cred {
            a: nym.a * γ,
            b: nym.b * γ,
            A: A * γ,
            B: B * γ,
            T1,
            T2,
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
        source_key: OrgPublicKey,
    ) -> Result {
        cred.T1.verify(Publics {
            g1: &RISTRETTO_BASEPOINT_POINT,
            h1: source_key.points().1,
            g2: &cred.b,
            h2: &cred.A,
        })?;
        cred.T2.verify(Publics {
            g1: &RISTRETTO_BASEPOINT_POINT,
            h1: source_key.points().0,
            g2: &(cred.a + cred.A),
            h2: &cred.B,
        })?;
        dlog_eq::verify(
            user,
            Publics {
                g1: &nym.a,
                h1: &nym.b,
                g2: &cred.a,
                h2: &cred.b,
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
                g1: &nym.a,
                h1: &nym.b,
                g2: &cred.a,
                h2: &cred.b,
            },
            ProverSecrets {
                x: self.sk.key.exponent(),
            },
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::assert_matches::assert_matches;

    use curve25519_dalek::RistrettoPoint;
    use futures::{
        channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
        executor::block_on,
        future::try_join,
        io,
        sink::SinkExt as _,
        stream::StreamExt as _,
    };
    use merlin::Transcript;
    use rand::thread_rng;
    use serde::{Deserialize, Serialize};

    use crate::{
        key::{OrgSecretKey, UserSecretKey},
        transport::LocalTransport,
        Error, Nym,
    };

    use super::{Org, User};

    struct TestTransport(
        UnboundedSender<(String, Vec<u8>)>,
        UnboundedReceiver<(String, Vec<u8>)>,
    );

    impl TestTransport {
        pub fn new() -> (Self, Self) {
            let (s1, r2) = mpsc::unbounded();
            let (s2, r1) = mpsc::unbounded();
            (Self(s1, r1), Self(s2, r2))
        }
    }

    impl LocalTransport for TestTransport {
        async fn receive<V: for<'a> Deserialize<'a>>(
            &mut self,
            label: &'static [u8],
        ) -> Result<V, io::Error> {
            let label_display = String::from_utf8_lossy(label);
            let (recv_label, bytes) = self
                .1
                .next()
                .await
                .expect(&format!("expected `{label_display}`, got nothing"));
            assert_eq!(
                recv_label.as_bytes(),
                label,
                "expected `{label_display}`, got `{recv_label}`",
            );
            let value = serde_json::from_slice(&bytes).expect(&format!(
                "expected valid JSON to deserialize `{label_display}`",
            ));
            Ok(value)
        }

        async fn send<V: Serialize>(
            &mut self,
            label: &'static [u8],
            value: V,
        ) -> Result<(), io::Error> {
            let label_display = String::from_utf8_lossy(label);
            self.0
                .send((
                    label_display.clone().into(),
                    serde_json::to_vec(&value).expect(&format!(
                        "expected serialization of `{label_display}` to succeed"
                    )),
                ))
                .await
                .expect(&format!("expected sending of `{label_display}` to succeed"));
            Ok(())
        }
    }

    #[test]
    fn nym_generation() {
        let user = User::new(UserSecretKey::random(&mut thread_rng()));
        let org = Org::new(OrgSecretKey::random(&mut thread_rng()));

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let (n1, n2) = block_on(try_join(
            user.generate_nym(&mut u_channel),
            org.generate_nym(&mut o_channel),
        ))
        .unwrap();
        assert_eq!(n1, n2, "user and org should compute the same nym");
        assert_eq!(n1.a * user.sk.key.exponent(), n1.b, "nym should be valid");
    }

    #[test]
    fn nym_authentication() {
        let user = User::new(UserSecretKey::random(&mut thread_rng()));
        let org = Org::new(OrgSecretKey::random(&mut thread_rng()));

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let (nym, _) = block_on(try_join(
            user.generate_nym(&mut u_channel),
            org.generate_nym(&mut o_channel),
        ))
        .unwrap();

        let res = block_on(try_join(
            user.authenticate_nym(&mut u_channel, nym),
            org.authenticate_nym(&mut o_channel, nym),
        ));
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn cred_issuance() {
        let user = User::new(UserSecretKey::random(&mut thread_rng()));
        let org = Org::new(OrgSecretKey::random(&mut thread_rng()));

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let (nym, _) = block_on(try_join(
            user.generate_nym(&mut u_channel),
            org.generate_nym(&mut o_channel),
        ))
        .unwrap();

        let (cred, _) = block_on(try_join(
            user.issue_credential(&mut u_channel, nym, org.public_key()),
            org.issue_credential(&mut o_channel, nym),
        ))
        .unwrap();

        assert_eq!(cred.a * user.sk.key.exponent(), cred.b);
        assert_eq!(cred.b * org.sk.key2.exponent(), cred.A);
        assert_eq!((cred.a + cred.A) * org.sk.key1.exponent(), cred.B);
    }

    #[test]
    fn cred_transfer() {
        let user = User::new(UserSecretKey::random(&mut thread_rng()));
        let org1 = Org::new(OrgSecretKey::random(&mut thread_rng()));
        let org2 = Org::new(OrgSecretKey::random(&mut thread_rng()));

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let (nym, _) = block_on(try_join(
            user.generate_nym(&mut u_channel),
            org1.generate_nym(&mut o_channel),
        ))
        .unwrap();

        let (cred, _) = block_on(try_join(
            user.issue_credential(&mut u_channel, nym, org1.public_key()),
            org1.issue_credential(&mut o_channel, nym),
        ))
        .unwrap();

        let res = block_on(try_join(
            user.transfer_credential(&mut u_channel, nym, cred),
            org2.transfer_credential(&mut o_channel, nym, cred, org1.public_key()),
        ));
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn sign_with_nym() {
        let user = User::new(UserSecretKey::random(&mut thread_rng()));
        let org = Org::new(OrgSecretKey::random(&mut thread_rng()));

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let (n1, n2) = block_on(try_join(
            user.generate_nym(&mut u_channel),
            org.generate_nym(&mut o_channel),
        ))
        .unwrap();
        let make_t = || {
            let mut t = Transcript::new(b"test-transcript");
            t.append_message(b"test", b"please sign this!");
            t
        };
        let sig = user.sk.sign(make_t(), &n1);
        let res = n2.verify(make_t(), &sig);
        assert_matches!(res, Ok(_));

        let sig = user.sk.sign(Transcript::new(b"bad-transcript"), &n1);
        let res = n2.verify(make_t(), &sig);
        assert_matches!(res, Err(Error::BadSignature));

        let sig = user.sk.sign(
            make_t(),
            &Nym {
                a: RistrettoPoint::random(&mut thread_rng()),
                ..n1
            },
        );
        let res = n2.verify(make_t(), &sig);
        assert_matches!(res, Err(Error::BadSignature));
    }
}
