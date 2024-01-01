//! Pseudo*nym* generation and verification

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand::thread_rng;

use crate::{
    error::{Error, Result},
    key::{OrgPublicKey, OrgSecretKey, UserPublicKey, UserSecretKey},
    proof::{
        blind_dlog_eq::{self, DlogEqTranscript, ProverSecrets, VerifierSecrets},
        dlog_eq::{self, Publics},
    },
    transport::LocalTransport,
};

/// A pseudonym
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Nym {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A credential
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
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
    pk: UserPublicKey,
}

impl Org {
    /// Initializes a new organization with the given secret key
    pub fn new(sk: OrgSecretKey) -> Self {
        Self {
            pk: sk.public(),
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
            pk: sk.public(),
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
        let a1 = user.receive(b"a~").await?;
        let b1 = user.receive(b"b~").await?;
        let r = Scalar::random(&mut thread_rng());
        let a = r * a1;
        user.send(b"a", a).await?;
        let b: RistrettoPoint = user.receive(b"b").await?;
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

    /// Generates a pseudonym as the CA
    pub async fn generate_nym_as_ca<T: LocalTransport>(
        &self,
        user: &mut T,
        user_key: UserPublicKey,
    ) -> Result<Nym> {
        let a1 = user.receive(b"a~").await?;
        let b1 = user.receive(b"b~").await?;
        if a1 != RISTRETTO_BASEPOINT_POINT {
            return Err(Error::BadProof);
        }
        if b1 != user_key.point() {
            return Err(Error::BadProof);
        }
        let r = Scalar::random(&mut thread_rng());
        let a = r * a1;
        user.send(b"a", a).await?;
        let b: RistrettoPoint = user.receive(b"b").await?;
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
        self.generate_nym_impl(org, a1, b1).await
    }

    /// Generates a pseudonym with a CA
    pub async fn generate_nym_with_ca<T: LocalTransport>(&self, org: &mut T) -> Result<Nym> {
        let a1 = RISTRETTO_BASEPOINT_POINT;
        let b1 = self.pk.point();
        self.generate_nym_impl(org, a1, b1).await
    }

    async fn generate_nym_impl<T: LocalTransport>(
        &self,
        org: &mut T,
        a1: RistrettoPoint,
        b1: RistrettoPoint,
    ) -> Result<Nym> {
        org.send(b"a~", a1).await?;
        org.send(b"b~", b1).await?;
        let a = org.receive(b"a").await?;
        let b = self.sk.exponent() * a;
        org.send(b"b", b).await?;
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
                g: RISTRETTO_BASEPOINT_POINT,
                h: self.pk.points().1,
                g1: nym.b,
                h1: a1,
            },
            ProverSecrets {
                x: self.sk.exponents().1,
            },
        )
        .await?;
        blind_dlog_eq::prove(
            user,
            Publics {
                g: RISTRETTO_BASEPOINT_POINT,
                h: self.pk.points().0,
                g1: nym.a + a1,
                h1: b1,
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
                g: RISTRETTO_BASEPOINT_POINT,
                h: source_key.points().1,
                g1: nym.b,
                h1: a1,
            },
            VerifierSecrets { γ },
        )
        .await?;
        let t2 = blind_dlog_eq::verify(
            org,
            Publics {
                g: RISTRETTO_BASEPOINT_POINT,
                h: source_key.points().0,
                g1: nym.a + a1,
                h1: b1,
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
        source_key: OrgPublicKey,
    ) -> Result {
        cred.t1.verify(Publics {
            g: RISTRETTO_BASEPOINT_POINT,
            h: source_key.points().1,
            g1: cred.b,
            h1: cred.a1,
        })?;
        cred.t2.verify(Publics {
            g: RISTRETTO_BASEPOINT_POINT,
            h: source_key.points().0,
            g1: cred.a + cred.a1,
            h1: cred.b1,
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

#[cfg(test)]
mod test {
    use futures::{
        channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
        executor::block_on,
        future::try_join,
        io,
        sink::SinkExt as _,
        stream::StreamExt as _,
    };
    use serde::{Deserialize, Serialize};

    use crate::{
        key::{OrgSecretKey, UserSecretKey},
        transport::LocalTransport,
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
        let user = User::new(UserSecretKey::random());
        let org = Org::new(OrgSecretKey::random());

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let u_gen = user.generate_nym(&mut u_channel);
        let o_gen = org.generate_nym(&mut o_channel);

        let (n1, n2) = block_on(try_join(u_gen, o_gen)).unwrap();
        assert_eq!(n1, n2, "user and org should compute the same nym");
        assert_eq!(n1.a * user.sk.exponent(), n1.b, "nym should be valid");
    }

    #[test]
    fn nym_authentication() {
        let user = User::new(UserSecretKey::random());
        let org = Org::new(OrgSecretKey::random());

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let u_gen = user.generate_nym(&mut u_channel);
        let o_gen = org.generate_nym(&mut o_channel);
        let (nym, _) = block_on(try_join(u_gen, o_gen)).unwrap();

        let u_auth = user.authenticate_nym(&mut u_channel, nym);
        let o_auth = org.authenticate_nym(&mut o_channel, nym);

        let res = block_on(try_join(u_auth, o_auth));
        assert!(matches!(res, Ok(_)), "expected Ok, found {res:?}");
    }

    #[test]
    fn cred_issuance() {
        let user = User::new(UserSecretKey::random());
        let org = Org::new(OrgSecretKey::random());

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let u_gen = user.generate_nym(&mut u_channel);
        let o_gen = org.generate_nym(&mut o_channel);
        let (nym, _) = block_on(try_join(u_gen, o_gen)).unwrap();

        let u_issue = user.issue_credential(&mut u_channel, nym, org.public_key());
        let o_issue = org.issue_credential(&mut o_channel, nym);

        let (cred, _) = block_on(try_join(u_issue, o_issue)).unwrap();

        assert_eq!(cred.a * user.sk.exponent(), cred.b);
        assert_eq!(cred.b * org.sk.exponents().1, cred.a1);
        assert_eq!((cred.a + cred.a1) * org.sk.exponents().0, cred.b1);
    }

    #[test]
    fn cred_transfer() {
        let user = User::new(UserSecretKey::random());
        let org1 = Org::new(OrgSecretKey::random());
        let org2 = Org::new(OrgSecretKey::random());

        let (mut u_channel, mut o_channel) = TestTransport::new();
        let u_gen = user.generate_nym(&mut u_channel);
        let o_gen = org1.generate_nym(&mut o_channel);
        let (nym, _) = block_on(try_join(u_gen, o_gen)).unwrap();

        let u_issue = user.issue_credential(&mut u_channel, nym, org1.public_key());
        let o_issue = org1.issue_credential(&mut o_channel, nym);

        let (cred, _) = block_on(try_join(u_issue, o_issue)).unwrap();

        let u_transfer = user.transfer_credential(&mut u_channel, nym, cred);
        let o_transfer = org2.transfer_credential(&mut o_channel, nym, cred, org1.public_key());

        let res = block_on(try_join(u_transfer, o_transfer));
        assert!(matches!(res, Ok(_)), "expected Ok, found {res:?}");
    }
}
