use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const SECRET_PREFIX: &str = "lenso_sa_";

#[derive(Clone)]
pub(crate) struct ReceiptCipher(Zeroizing<[u8; 32]>);

impl ReceiptCipher {
    pub(crate) fn derive(secret: &[u8]) -> Self {
        let digest = Sha256::digest(secret);
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(Zeroizing::new(key))
    }

    pub(crate) fn encrypt<T: Serialize>(
        &self,
        value: &T,
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), CryptoError> {
        let bytes = serde_json::to_vec(value).map_err(CryptoError::Serialize)?;
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(CryptoError::Random)?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| CryptoError::Invariant("invalid receipt key"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad })
            .map_err(|_| CryptoError::ReceiptEncryption)?;
        Ok((nonce, ciphertext))
    }

    pub(crate) fn decrypt<T: DeserializeOwned>(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<T, CryptoError> {
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::ReceiptDecryption)?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| CryptoError::Invariant("invalid receipt key"))?;
        let bytes = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::ReceiptDecryption)?;
        serde_json::from_slice(&bytes).map_err(CryptoError::Deserialize)
    }
}

impl fmt::Debug for ReceiptCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiptCipher(<redacted>)")
    }
}

#[derive(Clone)]
pub(crate) struct CredentialSecret {
    pub(crate) credential_id: String,
    wire: Zeroizing<String>,
}

impl CredentialSecret {
    pub(crate) fn generate() -> Result<Self, CryptoError> {
        let mut id = [0_u8; 18];
        let mut material = [0_u8; 32];
        getrandom::fill(&mut id).map_err(CryptoError::Random)?;
        getrandom::fill(&mut material).map_err(CryptoError::Random)?;
        let credential_id = format!("sac_{}", URL_SAFE_NO_PAD.encode(id));
        let wire = Zeroizing::new(format!(
            "{SECRET_PREFIX}{credential_id}.{}",
            URL_SAFE_NO_PAD.encode(material)
        ));
        Ok(Self {
            credential_id,
            wire,
        })
    }

    pub(crate) fn expose(&self) -> String {
        self.wire.to_string()
    }

    pub(crate) fn verifier(&self, pepper: &[u8]) -> Result<String, CryptoError> {
        hash_secret(&self.wire, pepper)
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialSecret")
            .field("credential_id", &self.credential_id)
            .field("wire", &"<redacted>")
            .finish()
    }
}

pub(crate) fn credential_id(secret: &str) -> Option<&str> {
    let (credential_id, material) = secret.strip_prefix(SECRET_PREFIX)?.split_once('.')?;
    (!credential_id.is_empty()
        && credential_id.len() <= 128
        && credential_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && material.len() >= 32
        && material.len() <= 128
        && material
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then_some(credential_id)
}

pub(crate) fn hash_secret(secret: &str, pepper: &[u8]) -> Result<String, CryptoError> {
    let input = peppered(secret, pepper);
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(CryptoError::Random)?;
    let salt = SaltString::encode_b64(&salt).map_err(CryptoError::PasswordHash)?;
    argon2id()
        .hash_password(&input, &salt)
        .map(|hash| hash.to_string())
        .map_err(CryptoError::PasswordHash)
}

pub(crate) fn verify_secret(secret: &str, pepper: &[u8], verifier: &str) -> bool {
    let Ok(hash) = PasswordHash::new(verifier) else {
        return false;
    };
    if hash.algorithm.as_str() != "argon2id" {
        return false;
    }
    argon2id()
        .verify_password(&peppered(secret, pepper), &hash)
        .is_ok()
}

fn argon2id() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

fn peppered(secret: &str, pepper: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(secret.len() + pepper.len() + 1));
    input.extend_from_slice(secret.as_bytes());
    input.push(0);
    input.extend_from_slice(pepper);
    input
}

#[derive(Debug, Error)]
pub(crate) enum CryptoError {
    #[error("failed to generate secure random material: {0}")]
    Random(getrandom::Error),
    #[error("failed to create Argon2id verifier: {0}")]
    PasswordHash(argon2::password_hash::Error),
    #[error("failed to serialize encrypted receipt: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize encrypted receipt: {0}")]
    Deserialize(serde_json::Error),
    #[error("failed to encrypt command receipt")]
    ReceiptEncryption,
    #[error("failed to decrypt command receipt")]
    ReceiptDecryption,
    #[error("cryptographic invariant failed: {0}")]
    Invariant(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_round_trip_requires_the_same_pepper() {
        let secret = CredentialSecret::generate().expect("secret");
        let verifier = secret
            .verifier(b"pepper one with enough material")
            .expect("hash");
        assert!(verifier.starts_with("$argon2id$v=19$"));
        assert!(verify_secret(
            &secret.expose(),
            b"pepper one with enough material",
            &verifier
        ));
        assert!(!verify_secret(
            &secret.expose(),
            b"different pepper with enough material",
            &verifier
        ));
        assert_eq!(
            credential_id(&secret.expose()),
            Some(secret.credential_id.as_str())
        );
        assert!(!format!("{secret:?}").contains(&secret.expose()));
    }

    #[test]
    fn receipt_cipher_binds_caller_operation_and_key() {
        let cipher = ReceiptCipher::derive(b"receipt key material at least thirty-two bytes");
        let value = serde_json::json!({"secret": null, "revision": "2"});
        let (nonce, ciphertext) = cipher
            .encrypt(&value, b"caller\0rotate\0key")
            .expect("encrypt");
        let decoded: serde_json::Value = cipher
            .decrypt(&nonce, &ciphertext, b"caller\0rotate\0key")
            .expect("decrypt");
        assert_eq!(decoded, value);
        assert!(
            cipher
                .decrypt::<serde_json::Value>(&nonce, &ciphertext, b"caller\0rotate\0other")
                .is_err()
        );
    }

    #[test]
    fn command_receipt_debug_is_redacted() {
        let claim = crate::storage::CommandClaim::CompletedSuccess {
            nonce: b"nonce secret".to_vec(),
            ciphertext: b"ciphertext secret".to_vec(),
        };
        let debug = format!("{claim:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("nonce secret"));
        assert!(!debug.contains("ciphertext secret"));
    }
}
