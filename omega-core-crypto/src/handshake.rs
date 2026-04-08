use hkdf::Hkdf;
use rand::rngs::OsRng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CryptoError, RawKeyMaterial, SessionKeys};

pub const HANDSHAKE_SECRET_LEN: usize = 32;
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const CHACHA20_NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct X25519Keypair {
    private: StaticSecret,
    public: [u8; X25519_PUBLIC_KEY_LEN],
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private).to_bytes();
        Self { private, public }
    }

    pub fn public(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public
    }

    pub fn diffie_hellman(
        &self,
        peer_public: &[u8; X25519_PUBLIC_KEY_LEN],
    ) -> [u8; HANDSHAKE_SECRET_LEN] {
        let peer = PublicKey::from(*peer_public);
        self.private.diffie_hellman(&peer).to_bytes()
    }
}

#[derive(Clone)]
pub struct HandshakeSecrets {
    pub session_keys: SessionKeys,
    pub flow_id: [u8; 16],
    pub app_secret: [u8; HANDSHAKE_SECRET_LEN],
    pub resumption_secret: [u8; HANDSHAKE_SECRET_LEN],
    pub update_secret: [u8; HANDSHAKE_SECRET_LEN],
}

pub fn hash_transcript(parts: &[&[u8]]) -> [u8; HANDSHAKE_SECRET_LEN] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; HANDSHAKE_SECRET_LEN];
    out.copy_from_slice(&digest);
    out
}

pub fn derive_credential_key(
    x25519_shared: &[u8; HANDSHAKE_SECRET_LEN],
    cookie: &[u8],
    connection_id: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"omega-v2-credential"), x25519_shared);
    let cookie_hash = Sha256::digest(cookie);
    let mut info = Vec::with_capacity(cookie_hash.len() + connection_id.len());
    info.extend_from_slice(&cookie_hash);
    info.extend_from_slice(connection_id);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

pub fn seal_with_key(
    key_bytes: &[u8; 32],
    nonce_bytes: [u8; CHACHA20_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(buf)
}

pub fn open_with_key(
    key_bytes: &[u8; 32],
    nonce_bytes: [u8; CHACHA20_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(plaintext.to_vec())
}

pub fn derive_hybrid_handshake_secrets(
    x25519_shared: &[u8; HANDSHAKE_SECRET_LEN],
    mlkem_shared: &[u8],
    transcript_hash: &[u8; HANDSHAKE_SECRET_LEN],
    is_server: bool,
) -> Result<HandshakeSecrets, CryptoError> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + mlkem_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(mlkem_shared);
    derive_secret_family(&ikm, transcript_hash, is_server)
}

pub fn derive_resumption_handshake_secrets(
    x25519_shared: &[u8; HANDSHAKE_SECRET_LEN],
    ticket_secret: &[u8; HANDSHAKE_SECRET_LEN],
    transcript_hash: &[u8; HANDSHAKE_SECRET_LEN],
    is_server: bool,
) -> Result<HandshakeSecrets, CryptoError> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + ticket_secret.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(ticket_secret);
    derive_secret_family(&ikm, transcript_hash, is_server)
}

pub fn derive_key_update_keys(
    update_secret: &[u8; HANDSHAKE_SECRET_LEN],
    next_epoch: u32,
    is_server: bool,
) -> Result<RawKeyMaterial, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"omega-v2-update"), update_secret);
    let mut info_a = Vec::with_capacity(32);
    info_a.extend_from_slice(b"omega-v2-key-a");
    info_a.extend_from_slice(&next_epoch.to_be_bytes());
    let mut info_b = Vec::with_capacity(32);
    info_b.extend_from_slice(b"omega-v2-key-b");
    info_b.extend_from_slice(&next_epoch.to_be_bytes());

    let mut key_a = [0u8; 32];
    let mut key_b = [0u8; 32];
    hk.expand(&info_a, &mut key_a)
        .map_err(|_| CryptoError::KeyDerivation)?;
    hk.expand(&info_b, &mut key_b)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let (send_key, recv_key) = if is_server {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };
    Ok(RawKeyMaterial { send_key, recv_key })
}

fn derive_secret_family(
    ikm: &[u8],
    transcript_hash: &[u8; HANDSHAKE_SECRET_LEN],
    is_server: bool,
) -> Result<HandshakeSecrets, CryptoError> {
    let root = Hkdf::<Sha256>::new(Some(b"omega-v2-root"), ikm);
    let app_secret = expand_labeled_secret(&root, b"omega-v2-app-0", transcript_hash)?;
    let resumption_secret = expand_labeled_secret(&root, b"omega-v2-resume", transcript_hash)?;
    let update_secret = expand_labeled_secret(&root, b"omega-v2-update", transcript_hash)?;
    let flow_id = expand_flow_id(&root, transcript_hash)?;
    let raw_keys = derive_key_update_keys(&app_secret, 0, is_server)?;
    let session_keys = SessionKeys::from_raw_keys(&raw_keys)?;
    Ok(HandshakeSecrets {
        session_keys,
        flow_id,
        app_secret,
        resumption_secret,
        update_secret,
    })
}

fn expand_labeled_secret(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    transcript_hash: &[u8; HANDSHAKE_SECRET_LEN],
) -> Result<[u8; HANDSHAKE_SECRET_LEN], CryptoError> {
    let mut info = Vec::with_capacity(label.len() + transcript_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(transcript_hash);
    let mut out = [0u8; HANDSHAKE_SECRET_LEN];
    hk.expand(&info, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(out)
}

fn expand_flow_id(
    hk: &Hkdf<Sha256>,
    transcript_hash: &[u8; HANDSHAKE_SECRET_LEN],
) -> Result<[u8; 16], CryptoError> {
    let mut info = Vec::with_capacity(13 + transcript_hash.len());
    info.extend_from_slice(b"omega-v2-flow");
    info.extend_from_slice(transcript_hash);
    let mut out = [0u8; 16];
    hk.expand(&info, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_matches() {
        let a = X25519Keypair::generate();
        let b = X25519Keypair::generate();

        let a_shared = a.diffie_hellman(&b.public());
        let b_shared = b.diffie_hellman(&a.public());
        assert_eq!(a_shared, b_shared);
    }

    #[test]
    fn credential_key_seals_and_opens() {
        let key = derive_credential_key(&[7u8; 32], b"cookie", b"conn-123").unwrap();
        let nonce = [9u8; 12];
        let ciphertext = seal_with_key(&key, nonce, b"aad", b"secret-payload").unwrap();
        let plaintext = open_with_key(&key, nonce, b"aad", &ciphertext).unwrap();
        assert_eq!(plaintext, b"secret-payload");
    }

    #[test]
    fn hybrid_handshake_secrets_match_roles() {
        let transcript = hash_transcript(&[b"init", b"retry", b"auth"]);
        let server =
            derive_hybrid_handshake_secrets(&[1u8; 32], &[2u8; 32], &transcript, true).unwrap();
        let client =
            derive_hybrid_handshake_secrets(&[1u8; 32], &[2u8; 32], &transcript, false).unwrap();
        assert_eq!(server.flow_id, client.flow_id);
        assert_eq!(server.app_secret, client.app_secret);
        assert_eq!(server.resumption_secret, client.resumption_secret);
        assert_eq!(server.update_secret, client.update_secret);
    }

    #[test]
    fn key_update_changes_keys_per_epoch() {
        let epoch0 = derive_key_update_keys(&[0x55; 32], 0, true).unwrap();
        let epoch1 = derive_key_update_keys(&[0x55; 32], 1, true).unwrap();
        assert_ne!(epoch0.send_key, epoch1.send_key);
        assert_ne!(epoch0.recv_key, epoch1.recv_key);
    }
}
