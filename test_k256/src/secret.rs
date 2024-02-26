use fuel_types::Bytes32;

use core::{
    fmt,
    ops::Deref,
    str,
};

// use zeroize::Zeroize;

use crate::{
    // secp256::PublicKey,
    Error,
};

use crate::public::PublicKey;

#[cfg(feature = "random")]
use rand::{
    CryptoRng,
    RngCore,
};

/// Asymmetric secret key, guaranteed to be valid by construction
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SecretKey(Bytes32);

impl SecretKey {
    /// Memory length of the type
    pub const LEN: usize = Bytes32::LEN;
}

impl Deref for SecretKey {
    type Target = [u8; SecretKey::LEN];

    fn deref(&self) -> &[u8; SecretKey::LEN] {
        self.0.deref()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<SecretKey> for [u8; SecretKey::LEN] {
    fn from(salt: SecretKey) -> [u8; SecretKey::LEN] {
        salt.0.into()
    }
}

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<::k256::SecretKey> for SecretKey {
    fn from(s: ::k256::SecretKey) -> Self {
        let mut raw_bytes = [0u8; Self::LEN];
        raw_bytes.copy_from_slice(&s.to_bytes());
        Self(Bytes32::from(raw_bytes))
    }
}

impl From<&SecretKey> for ::k256::SecretKey {
    fn from(sk: &SecretKey) -> Self {
        ::k256::SecretKey::from_bytes(&(*sk.0).into())
            .expect("SecretKey is guaranteed to be valid")
    }
}

impl SecretKey {
    /// Create a new random secret
    #[cfg(feature = "random")]
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        crate::random_secret(rng)
    }

    /// Return the curve representation of this secret.
    pub fn public_key(&self) -> PublicKey {
        crate::public_key(self).into()
    }
}

impl TryFrom<Bytes32> for SecretKey {
    type Error = Error;

    fn try_from(b: Bytes32) -> Result<Self, Self::Error> {
        match k256::SecretKey::from_bytes((&*b).into()) {
            Ok(_) => Ok(Self(b)),
            Err(_) => Err(Error::InvalidSecretKey),
        }
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Bytes32::try_from(slice)
            .map_err(|_| Error::InvalidSecretKey)
            .and_then(SecretKey::try_from)
    }
}

impl str::FromStr for SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bytes32::from_str(s)
            .map_err(|_| Error::InvalidSecretKey)
            .and_then(SecretKey::try_from)
    }
}
