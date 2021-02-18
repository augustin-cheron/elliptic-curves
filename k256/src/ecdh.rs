//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a high-level interface for performing ephemeral
//! Diffie-Hellman key exchanges using the secp256k1 elliptic curve.
//!
//! # Usage
//!
//! This usage example is from the perspective of two participants in the
//! exchange, nicknamed "Alice" and "Bob".
//!
//! ```
//! use k256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Alice
//! let alice_secret = EphemeralSecret::random(&mut OsRng);
//! let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());
//!
//! // Bob
//! let bob_secret = EphemeralSecret::random(&mut OsRng);
//! let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());
//!
//! // Alice decodes Bob's serialized public key and computes a shared secret from it
//! let bob_public = PublicKey::from_sec1_bytes(bob_pk_bytes.as_ref())
//!     .expect("bob's public key is invalid!"); // In real usage, don't panic, handle this!
//!
//! let alice_shared = alice_secret.diffie_hellman(&bob_public);
//!
//! // Bob deocdes Alice's serialized public key and computes the same shared secret
//! let alice_public = PublicKey::from_sec1_bytes(alice_pk_bytes.as_ref())
//!     .expect("alice's public key is invalid!"); // In real usage, don't panic, handle this!
//!
//! let bob_shared = bob_secret.diffie_hellman(&alice_public);
//!
//! // Both participants arrive on the same shared secret
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use crate::{AffinePoint, Secp256k1};
use crate::{PublicKey, SecretKey};

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<Secp256k1>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<Secp256k1>;

/// Low-level Elliptic Curve Diffie-Hellman (ECDH) function.
///
/// Whenever possible, we recommend using the high-level ECDH ephemeral API
/// provided by [`EphemeralSecret`].
///
/// However, if you are implementing a protocol which requires a static scalar
/// value as part of an ECDH exchange, this API can be used to compute a
/// [`SharedSecret`] from that value.
///
/// ```ignore
/// let shared_secret = k256::ecdh::diffie_hellman(&secret_key,&public_key);
/// ```
pub fn diffie_hellman(secret_key: &SecretKey, public_key: &PublicKey) -> SharedSecret {
    elliptic_curve::ecdh::diffie_hellman(secret_key.secret_scalar(), public_key.as_affine())
}

impl From<&AffinePoint> for SharedSecret {
    fn from(affine: &AffinePoint) -> SharedSecret {
        affine.x.to_bytes().into()
    }
}
