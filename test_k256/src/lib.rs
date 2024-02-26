mod error;
mod message;
mod hasher;
mod public;
mod secret;

mod signature_format;

pub use error::Error;
pub use hasher::Hasher;
use message::Message;
use secret::SecretKey;

use signature_format::{
    decode_signature,
    encode_signature,
    RecoveryId as SecpRecoveryId,
};

use k256::{
    ecdsa::{
        RecoveryId,
        VerifyingKey,
    },
    EncodedPoint,
    PublicKey,
};

use rand::{
    CryptoRng,
    RngCore,
};

/// Generates a random secret key
pub fn random_secret(rng: &mut (impl CryptoRng + RngCore)) -> SecretKey {
    k256::SecretKey::random(rng).into()
}

/// Derives the public key from a given secret key
pub fn public_key(secret: &SecretKey) -> PublicKey {
    let sk: k256::SecretKey = (&secret.clone()).into();
    let sk: k256::ecdsa::SigningKey = sk.into();
    let vk = sk.verifying_key();
    vk.into()
}


/// Recover the public key from a signature.
///
/// It takes the signature as owned because this operation is not idempotent. The
/// taken signature will not be recoverable. Signatures are meant to be
/// single use, so this avoids unnecessary copy.
pub fn recover(signature: [u8; 64], message: &Message) -> Result<PublicKey, Error> {
    let (sig, recid) = decode_signature(signature);
    let sig =
        k256::ecdsa::Signature::from_slice(&sig).map_err(|_| Error::InvalidSignature)?;
    let vk = VerifyingKey::recover_from_prehash(&**message, &sig, recid.into())
        .map_err(|_| Error::InvalidSignature)?;
    Ok(PublicKey::from(&vk))
}


mod tests {
    use fuel_types::Bytes32;
    use super::*;

    #[test]
    fn no_std() {
        let raw_secret: [u8; 32] = [
            0x99, 0xe8, 0x7b, 0xe, 0x91, 0x58, 0x53, 0x1e, 0xee, 0xb5, 0x3, 0xff, 0x15,
            0x26, 0x6e, 0x2b, 0x23, 0xc2, 0xa2, 0x50, 0x7b, 0x13, 0x8c, 0x9d, 0x1b, 0x1f,
            0x2a, 0xb4, 0x58, 0xdf, 0x2d, 0x6,
        ];
        let secret = SecretKey::try_from(Bytes32::from(raw_secret)).unwrap();
        let public = public_key(&secret);

        let message = Message::new(b"Every secret creates a potential failure point.");

        //let signature = sign(&secret, &message);
        //verify(signature, *public, &message).expect("Verification failed");

        let signature = [117, 133, 115, 69, 243, 18, 74, 27, 216, 155, 251, 46, 36, 189, 175, 146, 219, 0, 26, 111, 205, 62, 149, 25, 16, 37, 122, 158, 103, 175, 131, 164, 247, 171, 7, 36, 240, 226, 74, 230, 221, 84, 59, 0, 20, 167, 111, 211, 10, 102, 134, 147, 28, 151, 223, 1, 204, 50, 131, 124, 202, 180, 176, 248];
        let recovered = recover(signature, &message).expect("Recovery failed");

        assert_eq!(public, recovered);
    }
}