/// Crypto module — ChaCha20-Poly1305 AEAD + HKDF key derivation.
///
/// Uses `ring` for AEAD (SIMD-accelerated) and `hkdf`+`sha2` for key derivation.
/// Provides `SessionKeys` for per-connection encrypt/decrypt with auto-incrementing nonces.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derived session keys for one direction of traffic.
#[derive(Clone)]
pub struct SessionKeys {
    /// Encryption key (send direction).
    send_key: LessSafeKey,
    /// Decryption key (receive direction).
    recv_key: LessSafeKey,
    /// Auto-incrementing send nonce counter.
    send_nonce: u64,
    /// Receive nonce counter (for validation only; replay filter handles anti-replay).
    recv_nonce_counter: u64,
}

/// Raw key material before constructing ring keys.
pub struct RawKeyMaterial {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

impl SessionKeys {
    /// Derive session keys from a shared secret (ML-KEM output).
    ///
    /// Uses HKDF-SHA256 with the role label to derive independent send/recv keys.
    /// `is_server` determines which derived key is send vs recv.
    pub fn from_shared_secret(shared_secret: &[u8], is_server: bool) -> Result<Self, CryptoError> {
        let raw = Self::derive_raw_keys(shared_secret, is_server)?;
        Self::from_raw_keys(&raw)
    }

    /// Derive raw key bytes from the shared secret.
    pub fn derive_raw_keys(shared_secret: &[u8], is_server: bool) -> Result<RawKeyMaterial, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(b"omega-vpn-v1"), shared_secret);

        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];

        hk.expand(b"omega-traffic-key-a", &mut key_a)
            .map_err(|_| CryptoError::KeyDerivation)?;
        hk.expand(b"omega-traffic-key-b", &mut key_b)
            .map_err(|_| CryptoError::KeyDerivation)?;

        // Server sends with key_a, receives with key_b.
        // Client sends with key_b, receives with key_a.
        let (send, recv) = if is_server {
            (key_a, key_b)
        } else {
            (key_b, key_a)
        };

        Ok(RawKeyMaterial {
            send_key: send,
            recv_key: recv,
        })
    }

    /// Construct SessionKeys from raw 32-byte key material.
    pub fn from_raw_keys(raw: &RawKeyMaterial) -> Result<Self, CryptoError> {
        let send_unbound = UnboundKey::new(&CHACHA20_POLY1305, &raw.send_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let recv_unbound = UnboundKey::new(&CHACHA20_POLY1305, &raw.recv_key)
            .map_err(|_| CryptoError::InvalidKey)?;

        Ok(Self {
            send_key: LessSafeKey::new(send_unbound),
            recv_key: LessSafeKey::new(recv_unbound),
            send_nonce: 0,
            recv_nonce_counter: 0,
        })
    }

    /// Encrypt a packet in-place.
    ///
    /// `plaintext_buf` must have room for 16 additional bytes (Poly1305 tag)
    /// appended at the end. The `aad` (Additional Authenticated Data) should
    /// include the RTP + Omega headers to bind them to the ciphertext.
    ///
    /// Returns the nonce used (for sequencing) and the new length including tag.
    pub fn encrypt_in_place(
        &mut self,
        plaintext_buf: &mut Vec<u8>,
        aad: &[u8],
    ) -> Result<u64, CryptoError> {
        let nonce_val = self.send_nonce;
        self.send_nonce += 1;

        let nonce_bytes = make_nonce_bytes(nonce_val);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        self.send_key
            .seal_in_place_append_tag(nonce, Aad::from(aad), plaintext_buf)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(nonce_val)
    }

    /// Decrypt a packet in-place.
    ///
    /// `ciphertext_buf` contains the encrypted data + 16-byte tag.
    /// Returns a slice of the decrypted plaintext (subslice of the input).
    pub fn decrypt_in_place<'a>(
        &mut self,
        ciphertext_buf: &'a mut [u8],
        nonce_val: u64,
        aad: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        let nonce_bytes = make_nonce_bytes(nonce_val);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let plaintext = self
            .recv_key
            .open_in_place(nonce, Aad::from(aad), ciphertext_buf)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.recv_nonce_counter = self.recv_nonce_counter.max(nonce_val + 1);

        Ok(plaintext)
    }

    /// Get current send nonce value (useful for sequencing).
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }
}

/// Construct a 96-bit (12-byte) nonce from a u64 counter.
///
/// Format: [0x00; 4] ++ counter.to_le_bytes()
/// The leading 4 zero bytes act as implicit fixed field.
#[inline]
fn make_nonce_bytes(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Derive a FlowID from the shared secret.
///
/// Uses HKDF with a separate label so the FlowID is independent of traffic keys.
pub fn derive_flow_id(shared_secret: &[u8]) -> Result<[u8; 16], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"omega-vpn-v1"), shared_secret);
    let mut flow_id = [0u8; 16];
    hk.expand(b"omega-flow-id", &mut flow_id)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(flow_id)
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    KeyDerivation,
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyDerivation => write!(f, "HKDF key derivation failed"),
            Self::InvalidKey => write!(f, "invalid key material"),
            Self::EncryptionFailed => write!(f, "AEAD encryption failed"),
            Self::DecryptionFailed => write!(f, "AEAD decryption failed (bad tag or nonce)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shared_secret() -> Vec<u8> {
        vec![0x42u8; 32] // Simulated KEM output
    }

    #[test]
    fn test_key_derivation_produces_different_keys() {
        let raw = SessionKeys::derive_raw_keys(&test_shared_secret(), true).unwrap();
        assert_ne!(raw.send_key, raw.recv_key);
    }

    #[test]
    fn test_server_client_keys_are_swapped() {
        let server_raw = SessionKeys::derive_raw_keys(&test_shared_secret(), true).unwrap();
        let client_raw = SessionKeys::derive_raw_keys(&test_shared_secret(), false).unwrap();
        assert_eq!(server_raw.send_key, client_raw.recv_key);
        assert_eq!(server_raw.recv_key, client_raw.send_key);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let shared_secret = test_shared_secret();
        let mut server = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        let mut client = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();

        let plaintext = b"tunnel packet payload data here!";
        let aad = b"rtp+omega headers";

        // Server encrypts
        let mut buf = plaintext.to_vec();
        let nonce = server.encrypt_in_place(&mut buf, aad).unwrap();

        // Client decrypts
        let decrypted = client.decrypt_in_place(&mut buf, nonce, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let shared_secret = test_shared_secret();
        let mut server = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        let mut client = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();

        let mut buf = b"secret data".to_vec();
        let nonce = server.encrypt_in_place(&mut buf, b"correct aad").unwrap();

        let result = client.decrypt_in_place(&mut buf, nonce, b"wrong aad");
        assert_eq!(result, Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let shared_secret = test_shared_secret();
        let mut server = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        let mut client = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();

        let mut buf = b"secret data".to_vec();
        let _nonce = server.encrypt_in_place(&mut buf, b"aad").unwrap();

        let result = client.decrypt_in_place(&mut buf, 999, b"aad"); // wrong nonce
        assert_eq!(result, Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_nonce_auto_increment() {
        let shared_secret = test_shared_secret();
        let mut keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();

        let mut buf1 = b"pkt1".to_vec();
        let n1 = keys.encrypt_in_place(&mut buf1, b"").unwrap();
        let mut buf2 = b"pkt2".to_vec();
        let n2 = keys.encrypt_in_place(&mut buf2, b"").unwrap();

        assert_eq!(n1, 0);
        assert_eq!(n2, 1);
    }

    #[test]
    fn test_flow_id_derivation() {
        let fid1 = derive_flow_id(&test_shared_secret()).unwrap();
        let fid2 = derive_flow_id(&test_shared_secret()).unwrap();
        assert_eq!(fid1, fid2); // Deterministic

        let fid3 = derive_flow_id(&[0x43u8; 32]).unwrap();
        assert_ne!(fid1, fid3); // Different secret → different FlowID
    }

    #[test]
    fn test_multiple_packets() {
        let shared_secret = test_shared_secret();
        let mut server = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        let mut client = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();

        for i in 0..100u32 {
            let payload = format!("packet-{}", i);
            let aad = format!("hdr-{}", i);
            let mut buf = payload.as_bytes().to_vec();
            let nonce = server.encrypt_in_place(&mut buf, aad.as_bytes()).unwrap();
            let decrypted = client
                .decrypt_in_place(&mut buf, nonce, aad.as_bytes())
                .unwrap();
            assert_eq!(decrypted, payload.as_bytes());
        }
    }
}
