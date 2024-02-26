use core::convert::Infallible;

/// Crypto error variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Error {
    /// Invalid secp256k1 secret key
    InvalidSecretKey,

    /// Invalid secp256k1 public key
    InvalidPublicKey,

    /// Invalid secp256k1 signature message
    InvalidMessage,

    /// Invalid secp256k1 signature
    InvalidSignature,

    /// Coudln't sign the message
    FailedToSign,

    /// The provided key wasn't found
    KeyNotFound,

    /// The keystore isn't available or is corrupted
    KeystoreNotAvailable,

    /// Out of preallocated memory
    NotEnoughMemory,

    /// Invalid mnemonic phrase
    InvalidMnemonic,

    /// Bip32-related error
    Bip32Error,
}

impl From<Error> for Infallible {
    fn from(_: Error) -> Infallible {
        unreachable!()
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Error {
        unreachable!()
    }
}