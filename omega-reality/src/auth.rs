//! XTLS REALITY authentication scheme.
//!
//! The client embeds 32 bytes of authentication material in the TLS 1.3
//! `session_id` field of its `ClientHello`. The server combines those bytes
//! with the client's X25519 `key_share` and its own long-term X25519 secret
//! to decide whether the connection is from an authentic Omega client
//! (proceed with the REALITY handshake) or from a stranger / DPI probe
//! (route to the transparent proxy fallback).
//!
//! Scheme (simpler than upstream Xray Reality but preserves the same
//! security properties — only a peer who knows `server_long_term_pubkey`
//! can produce a passing tag, and only the server can verify it):
//!
//! ```text
//! auth_key   = X25519(client_ephemeral_secret, server_long_term_pubkey)
//!            = X25519(server_long_term_secret, client_ephemeral_pubkey)
//! tag        = HMAC-SHA256(auth_key, "reality-auth"||0x01||short_id)[..24]
//! session_id = short_id (8B) || tag (24B)
//! ```
//!
//! `short_id` is an 8-byte tag chosen from the server's
//! `OMEGA_REALITY_SHORT_IDS` whitelist. An all-zero `short_id` is treated
//! as a wildcard so simple deployments that don't need per-client tagging
//! can leave the list empty.
//!
//! The same shared `auth_key` is also reused to derive a key for the
//! REALITY-style `CertificateVerify` MAC so the client can verify that the
//! server holds `server_long_term_secret`.

use ring::hmac;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub const SESSION_ID_LEN: usize = 32;
pub const SHORT_ID_LEN: usize = 8;
pub const AUTH_TAG_LEN: usize = 24;
pub const AUTH_KEY_LEN: usize = 32;
pub const CV_SIGNATURE_LEN: usize = 64;

const AUTH_LABEL: &[u8] = b"reality-auth\x01";
const CV_KEY_LABEL: &[u8] = b"reality cv key\x01";
const CV_TAG1_LABEL: &[u8] = b"TLS 1.3, server CertificateVerify\x01";
const CV_TAG2_LABEL: &[u8] = b"TLS 1.3, server CertificateVerify\x02";

/// X25519 shared secret between the two sides.
pub fn derive_auth_key(
    my_secret: &StaticSecret,
    peer_pubkey: &PublicKey,
) -> [u8; AUTH_KEY_LEN] {
    let shared = my_secret.diffie_hellman(peer_pubkey);
    let mut out = [0u8; AUTH_KEY_LEN];
    out.copy_from_slice(shared.as_bytes());
    out
}

/// Compute the 24-byte HMAC tag binding `short_id` to `auth_key`.
pub fn compute_auth_tag(
    auth_key: &[u8; AUTH_KEY_LEN],
    short_id: &[u8; SHORT_ID_LEN],
) -> [u8; AUTH_TAG_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, auth_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(AUTH_LABEL);
    ctx.update(short_id);
    let tag = ctx.sign();
    let mut out = [0u8; AUTH_TAG_LEN];
    out.copy_from_slice(&tag.as_ref()[..AUTH_TAG_LEN]);
    out
}

/// Client-side: build a session_id from a short_id and an auth_key.
pub fn encode_session_id(
    short_id: &[u8; SHORT_ID_LEN],
    auth_key: &[u8; AUTH_KEY_LEN],
) -> [u8; SESSION_ID_LEN] {
    let tag = compute_auth_tag(auth_key, short_id);
    let mut sid = [0u8; SESSION_ID_LEN];
    sid[..SHORT_ID_LEN].copy_from_slice(short_id);
    sid[SHORT_ID_LEN..].copy_from_slice(&tag);
    sid
}

#[derive(Debug, Clone, Copy)]
pub enum AuthVerdict {
    /// Authentic Omega client. The short_id is forwarded so the caller can
    /// log it / use it for per-client rate limits.
    Authentic {
        short_id: [u8; SHORT_ID_LEN],
        auth_key: [u8; AUTH_KEY_LEN],
    },
    /// Stranger / DPI probe; route to the proxy fallback.
    Foreign,
}

/// Server-side verification.
///
/// `allowed_short_ids` is the whitelist from `OMEGA_REALITY_SHORT_IDS`.
/// An empty whitelist means we only accept the wildcard short_id (all zeros).
pub fn verify_session_id(
    session_id: &[u8],
    server_secret: &StaticSecret,
    client_ephemeral_pubkey: &PublicKey,
    allowed_short_ids: &[[u8; SHORT_ID_LEN]],
) -> AuthVerdict {
    if session_id.len() != SESSION_ID_LEN {
        return AuthVerdict::Foreign;
    }
    let mut short_id = [0u8; SHORT_ID_LEN];
    short_id.copy_from_slice(&session_id[..SHORT_ID_LEN]);

    let wildcard = short_id == [0u8; SHORT_ID_LEN];
    if !wildcard && !allowed_short_ids.iter().any(|id| *id == short_id) {
        return AuthVerdict::Foreign;
    }
    let auth_key = derive_auth_key(server_secret, client_ephemeral_pubkey);
    let expected_tag = compute_auth_tag(&auth_key, &short_id);
    let presented_tag = &session_id[SHORT_ID_LEN..];
    if bool::from(expected_tag.ct_eq(presented_tag)) {
        AuthVerdict::Authentic { short_id, auth_key }
    } else {
        AuthVerdict::Foreign
    }
}

/// Derive a 32-byte key used for the REALITY CertificateVerify MAC.
pub fn derive_cv_signature_key(auth_key: &[u8; AUTH_KEY_LEN]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, auth_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(CV_KEY_LABEL);
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// 64-byte pseudo-signature: HMAC over the transcript hash plus a second
/// independent HMAC for padding, so the on-wire value looks like a normal
/// 64-byte Ed25519 signature.
pub fn compute_reality_cv_signature(
    cv_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> [u8; CV_SIGNATURE_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, cv_key);

    let mut ctx1 = hmac::Context::with_key(&key);
    ctx1.update(CV_TAG1_LABEL);
    ctx1.update(transcript_hash);
    let tag1 = ctx1.sign();

    let mut ctx2 = hmac::Context::with_key(&key);
    ctx2.update(CV_TAG2_LABEL);
    ctx2.update(transcript_hash);
    let tag2 = ctx2.sign();

    let mut out = [0u8; CV_SIGNATURE_LEN];
    out[..32].copy_from_slice(tag1.as_ref());
    out[32..].copy_from_slice(tag2.as_ref());
    out
}

/// Client-side: verify a REALITY CertificateVerify signature.
pub fn verify_reality_cv_signature(
    cv_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    signature: &[u8],
) -> bool {
    if signature.len() != CV_SIGNATURE_LEN {
        return false;
    }
    let expected = compute_reality_cv_signature(cv_key, transcript_hash);
    bool::from(expected.ct_eq(signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fake_keys() -> (StaticSecret, PublicKey, StaticSecret, PublicKey) {
        let server_secret = StaticSecret::random_from_rng(&mut OsRng);
        let server_pub = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(&mut OsRng);
        let client_pub = PublicKey::from(&client_secret);
        (server_secret, server_pub, client_secret, client_pub)
    }

    #[test]
    fn auth_round_trip_succeeds_with_wildcard_short_id() {
        let (server_secret, server_pub, client_secret, client_pub) = fake_keys();
        // Client side: derive auth_key from client_secret + server_pub
        let auth_key_client = derive_auth_key(&client_secret, &server_pub);
        let short_id = [0u8; SHORT_ID_LEN];
        let sid = encode_session_id(&short_id, &auth_key_client);

        let verdict = verify_session_id(&sid, &server_secret, &client_pub, &[]);
        match verdict {
            AuthVerdict::Authentic { short_id: returned, .. } => {
                assert_eq!(returned, short_id);
            }
            AuthVerdict::Foreign => panic!("authentic client rejected as Foreign"),
        }
    }

    #[test]
    fn auth_round_trip_succeeds_with_whitelisted_short_id() {
        let (server_secret, server_pub, client_secret, client_pub) = fake_keys();
        let auth_key_client = derive_auth_key(&client_secret, &server_pub);
        let short_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let sid = encode_session_id(&short_id, &auth_key_client);
        let other = [0xAA; SHORT_ID_LEN];

        let verdict =
            verify_session_id(&sid, &server_secret, &client_pub, &[short_id, other]);
        assert!(matches!(verdict, AuthVerdict::Authentic { .. }));
    }

    #[test]
    fn auth_with_unknown_short_id_is_foreign() {
        let (server_secret, server_pub, client_secret, client_pub) = fake_keys();
        let auth_key_client = derive_auth_key(&client_secret, &server_pub);
        let short_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let sid = encode_session_id(&short_id, &auth_key_client);

        let verdict = verify_session_id(
            &sid,
            &server_secret,
            &client_pub,
            &[[0x99; SHORT_ID_LEN]],
        );
        assert!(matches!(verdict, AuthVerdict::Foreign));
    }

    #[test]
    fn auth_with_wrong_server_key_is_foreign() {
        // Client used the right pubkey, but the server we point at uses a
        // different secret — verification must fail.
        let (_, server_pub, client_secret, client_pub) = fake_keys();
        let wrong_server_secret = StaticSecret::random_from_rng(&mut OsRng);

        let auth_key_client = derive_auth_key(&client_secret, &server_pub);
        let short_id = [0u8; SHORT_ID_LEN];
        let sid = encode_session_id(&short_id, &auth_key_client);

        let verdict = verify_session_id(&sid, &wrong_server_secret, &client_pub, &[]);
        assert!(matches!(verdict, AuthVerdict::Foreign));
    }

    #[test]
    fn auth_with_random_session_id_is_foreign() {
        let (server_secret, _, _, client_pub) = fake_keys();
        let mut sid = [0u8; SESSION_ID_LEN];
        // Random short_id (not all zero) → not whitelisted → Foreign.
        sid[..SHORT_ID_LEN].copy_from_slice(&[0xDE; SHORT_ID_LEN]);
        for i in SHORT_ID_LEN..SESSION_ID_LEN {
            sid[i] = i as u8;
        }
        let verdict = verify_session_id(&sid, &server_secret, &client_pub, &[]);
        assert!(matches!(verdict, AuthVerdict::Foreign));
    }

    #[test]
    fn cv_signature_round_trip() {
        let auth_key = [0xABu8; AUTH_KEY_LEN];
        let cv_key = derive_cv_signature_key(&auth_key);
        let transcript = [0xCDu8; 32];
        let sig = compute_reality_cv_signature(&cv_key, &transcript);
        assert!(verify_reality_cv_signature(&cv_key, &transcript, &sig));

        // Wrong transcript → fail.
        let bad_transcript = [0xCEu8; 32];
        assert!(!verify_reality_cv_signature(&cv_key, &bad_transcript, &sig));
    }

    #[test]
    fn cv_signature_wrong_key_fails() {
        let auth_key_a = [0xABu8; AUTH_KEY_LEN];
        let auth_key_b = [0xACu8; AUTH_KEY_LEN];
        let cv_key_a = derive_cv_signature_key(&auth_key_a);
        let cv_key_b = derive_cv_signature_key(&auth_key_b);
        let transcript = [0xCDu8; 32];
        let sig = compute_reality_cv_signature(&cv_key_a, &transcript);
        assert!(!verify_reality_cv_signature(&cv_key_b, &transcript, &sig));
    }

    #[test]
    fn cv_signature_length_matches_ed25519() {
        let cv_key = [0xABu8; 32];
        let transcript = [0xCDu8; 32];
        let sig = compute_reality_cv_signature(&cv_key, &transcript);
        assert_eq!(sig.len(), 64); // matches Ed25519 signature size
    }
}
