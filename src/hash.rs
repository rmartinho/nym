//! Hash functions for nyms

use std::marker::PhantomData;

use curve25519_dalek::{RistrettoPoint, Scalar};
use digest::{
    generic_array::ArrayLength, Digest, FixedOutput, HashMarker, OutputSizeUser, Update, XofReader,
};
use merlin::Transcript;

/// A transcript-based protocol interface
pub trait TranscriptProtocol {
    /// Commits a value, with a given label for framing
    fn commit<M: Transcribe + ?Sized>(&mut self, label: &'static [u8], m: &M);

    /// Retrieves a challenge, with a given label for framing
    fn challenge<M: Challenge>(&mut self, label: &'static [u8]) -> M;
}

impl TranscriptProtocol for Transcript {
    fn commit<M: Transcribe + ?Sized>(&mut self, label: &'static [u8], m: &M) {
        m.append_to(self, label)
    }

    fn challenge<C: Challenge>(&mut self, label: &'static [u8]) -> C {
        C::challenge_from(self, label)
    }
}

/// A transcript-based hash
pub trait TranscriptDigest {
    /// Produces a Digest from all the data that was appended
    fn into_digest<N: ArrayLength<u8> + 'static>(self) -> impl Digest<OutputSize = N>;

    /// Creates a XOF reader object to produce a variable-size hash
    fn into_xof(self) -> impl XofReader;
}

impl TranscriptDigest for Transcript {
    fn into_digest<N: ArrayLength<u8> + 'static>(self) -> impl Digest<OutputSize = N> {
        TranscriptDigestImpl(self, PhantomData)
    }
    fn into_xof(self) -> impl XofReader {
        TranscriptXofReaderImpl(self)
    }
}

struct TranscriptDigestImpl<N: ArrayLength<u8> + 'static>(Transcript, PhantomData<N>);

impl<N: ArrayLength<u8> + 'static> HashMarker for TranscriptDigestImpl<N> {}

impl<N: ArrayLength<u8> + 'static> Default for TranscriptDigestImpl<N> {
    fn default() -> Self {
        Self(Transcript::new(b"$hash"), PhantomData)
    }
}

impl<N: ArrayLength<u8> + 'static> OutputSizeUser for TranscriptDigestImpl<N> {
    type OutputSize = N;
}

impl<N: ArrayLength<u8> + 'static> Update for TranscriptDigestImpl<N> {
    fn update(&mut self, data: &[u8]) {
        self.0.append_message(b"$update", data)
    }
}

impl<N: ArrayLength<u8> + 'static> FixedOutput for TranscriptDigestImpl<N> {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        self.0.challenge_bytes(b"$finalize", out)
    }
}

struct TranscriptXofReaderImpl(Transcript);

impl XofReader for TranscriptXofReaderImpl {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.challenge_bytes(b"$xof", buffer);
    }
}

/// A type that can be appended to a transcript
pub trait Transcribe {
    /// Appends this object to a transcript, with a given label for framing
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]);
}

/// A type that can be read from a transcript
pub trait Challenge {
    /// Obtains a challenge of this type from a transcript, with a given label for framing
    fn challenge_from(t: &mut Transcript, label: &'static [u8]) -> Self;
}

impl<T: Transcribe> Transcribe for [T] {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        self.len().append_to(t, label);
        for e in self.iter() {
            e.append_to(t, b"$");
        }
    }
}

impl<T: Transcribe> Transcribe for Vec<T> {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        self.as_slice().append_to(t, label);
    }
}

impl<'a, T: Transcribe> Transcribe for &'a T {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        (*self).append_to(t, label);
    }
}

impl Transcribe for bool {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, &[*self as u8]);
    }
}

impl Transcribe for usize {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, &(*self as u64).to_be_bytes());
    }
}

impl Transcribe for [u8] {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, self);
    }
}

impl Transcribe for str {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        t.append_message(label, self.as_bytes());
    }
}
impl Transcribe for String {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        self.as_str().append_to(t, label);
    }
}

impl Transcribe for Scalar {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        self.as_bytes().append_to(t, label);
    }
}

impl Challenge for Scalar {
    fn challenge_from(t: &mut Transcript, label: &'static [u8]) -> Self {
        let mut buf = [0; 64];
        t.challenge_bytes(label, &mut buf);
        Self::from_bytes_mod_order_wide(&buf)
    }
}

impl Transcribe for RistrettoPoint {
    fn append_to(&self, t: &mut Transcript, label: &'static [u8]) {
        self.compress().as_bytes().append_to(t, label);
    }
}
