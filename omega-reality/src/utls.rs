//! "uTLS"-style ClientHello builder for the REALITY transport.
//!
//! The goal is to make our ClientHello byte-for-byte close to what a current
//! Chrome on Windows would send, so that JA3/JA4 fingerprints are
//! indistinguishable from the masquerade target's regular visitors. Phase 4
//! ships with a minimal but realistic Chrome-131 profile (correct
//! cipher-suite order, extension order, key_share = X25519 only); Phase 6
//! refines it by capturing real Chrome traffic in Wireshark and matching
//! byte-for-byte.
//!
//! Notes on what is deliberately omitted in this profile:
//!   * **GREASE** entries (random extension/cipher-suite codepoints used by
//!     Chrome to keep middleboxes honest). These add fingerprinting overhead
//!     and we can introduce them in Phase 6 without breaking compatibility.
//!   * **Encrypted Client Hello (ECH)**. Chrome stable currently does not
//!     enable ECH by default in all builds; the REALITY upstream profile is
//!     `chrome_120_no_ech` family — we match.
//!   * **session_ticket** extension. We don't support TLS resumption so it
//!     is left out (matching `xtls-reality`'s default Chrome profile).

use anyhow::Result;
use crate::auth::SESSION_ID_LEN;
use crate::tls_messages::{
    record_header, wrap_handshake, Writer, CT_HANDSHAKE, EXT_ALPN, EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_SERVER_NAME, EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS, HS_CLIENT_HELLO, NG_SECP256R1, NG_X25519, SS_ECDSA_SECP256R1_SHA256,
    SS_ED25519, SS_RSA_PSS_RSAE_SHA256, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256, TLS_RANDOM_LEN, TLS_VERSION_13, TLS_VERSION_LEGACY,
};

/// Output of [`build_client_hello`]: the full TLS *record* bytes (5-byte
/// outer header + handshake header + ClientHello body), and the inner
/// `handshake` message bytes that need to feed the transcript hash.
pub struct ClientHelloBytes {
    pub record_wire: Vec<u8>,
    pub handshake_message: Vec<u8>,
}

pub struct ClientHelloPlan<'a> {
    pub server_name: &'a str,
    pub session_id: &'a [u8; SESSION_ID_LEN],
    pub client_random: &'a [u8; TLS_RANDOM_LEN],
    pub client_x25519_public: &'a [u8; 32],
    /// `Some(b"http/1.1")` to advertise ALPN; `None` to omit the extension.
    pub alpn_offer: Option<&'a [&'a [u8]]>,
}

pub fn build_client_hello(plan: &ClientHelloPlan<'_>) -> Result<ClientHelloBytes> {
    let mut body = Writer::new();

    // legacy_version
    body.push_u16(TLS_VERSION_LEGACY);
    // random
    body.push_slice(plan.client_random);
    // legacy_session_id (32 bytes — carrying our REALITY auth tag)
    body.vec_u8(|w| w.push_slice(plan.session_id))?;

    // cipher_suites (Chrome 131 — TLS 1.3 suites first, then a small set of
    // TLS 1.2 ECDHE-ECDSA / ECDHE-RSA for masquerade)
    body.vec_u16(|w| {
        // TLS 1.3
        w.push_u16(TLS_AES_128_GCM_SHA256);
        w.push_u16(TLS_AES_256_GCM_SHA384);
        w.push_u16(TLS_CHACHA20_POLY1305_SHA256);
        // TLS 1.2 (server will ignore — present only for fingerprint shape)
        w.push_u16(0xC02B); // ECDHE-ECDSA-AES128-GCM-SHA256
        w.push_u16(0xC02F); // ECDHE-RSA-AES128-GCM-SHA256
        w.push_u16(0xC02C); // ECDHE-ECDSA-AES256-GCM-SHA384
        w.push_u16(0xC030); // ECDHE-RSA-AES256-GCM-SHA384
        w.push_u16(0xCCA9); // ECDHE-ECDSA-CHACHA20-POLY1305
        w.push_u16(0xCCA8); // ECDHE-RSA-CHACHA20-POLY1305
        w.push_u16(0x009C); // RSA-AES128-GCM-SHA256
        w.push_u16(0x009D); // RSA-AES256-GCM-SHA384
        w.push_u16(0x002F); // RSA-AES128-CBC-SHA
        w.push_u16(0x0035); // RSA-AES256-CBC-SHA
    })?;

    // compression_methods (always [0] in TLS 1.3)
    body.vec_u8(|w| w.push_u8(0))?;

    // extensions
    body.vec_u16(|w| {
        // server_name
        write_extension(w, EXT_SERVER_NAME, |w| {
            w.vec_u16(|w| {
                w.push_u8(0); // host_name
                w.vec_u16(|w| w.push_slice(plan.server_name.as_bytes())).unwrap();
            })
            .unwrap();
        });
        // supported_groups: X25519 + secp256r1 (Chrome order)
        write_extension(w, EXT_SUPPORTED_GROUPS, |w| {
            w.vec_u16(|w| {
                w.push_u16(NG_X25519);
                w.push_u16(NG_SECP256R1);
            })
            .unwrap();
        });
        // signature_algorithms (Chrome order)
        write_extension(w, EXT_SIGNATURE_ALGORITHMS, |w| {
            w.vec_u16(|w| {
                w.push_u16(SS_ECDSA_SECP256R1_SHA256);
                w.push_u16(SS_RSA_PSS_RSAE_SHA256);
                w.push_u16(SS_ED25519);
                w.push_u16(0x0501); // rsa_pkcs1_sha384
                w.push_u16(0x0601); // rsa_pkcs1_sha512
                w.push_u16(0x0201); // rsa_pkcs1_sha256
            })
            .unwrap();
        });
        // ALPN
        if let Some(alpn_list) = plan.alpn_offer {
            write_extension(w, EXT_ALPN, |w| {
                w.vec_u16(|w| {
                    for proto in alpn_list {
                        w.vec_u8(|w| w.push_slice(proto)).unwrap();
                    }
                })
                .unwrap();
            });
        }
        // key_share — X25519 only (Chrome offers X25519 first, then
        // secp256r1, but we deliberately only ship X25519 keyshare for
        // REALITY — the server insists on X25519 anyway).
        write_extension(w, EXT_KEY_SHARE, |w| {
            w.vec_u16(|w| {
                w.push_u16(NG_X25519);
                w.vec_u16(|w| w.push_slice(plan.client_x25519_public)).unwrap();
            })
            .unwrap();
        });
        // psk_key_exchange_modes — we don't do PSK but Chrome always offers
        // psk_dhe_ke. Keeping it for fingerprint parity.
        write_extension(w, EXT_PSK_KEY_EXCHANGE_MODES, |w| {
            w.vec_u8(|w| w.push_u8(1)).unwrap(); // psk_dhe_ke
        });
        // supported_versions — TLS 1.3
        write_extension(w, EXT_SUPPORTED_VERSIONS, |w| {
            w.vec_u8(|w| w.push_u16(TLS_VERSION_13)).unwrap();
        });
    })?;

    let chlo_body = body.into_bytes();
    let chlo_hs = wrap_handshake(HS_CLIENT_HELLO, &chlo_body)?;
    let mut record = Vec::with_capacity(5 + chlo_hs.len());
    record.extend_from_slice(&record_header(CT_HANDSHAKE, chlo_hs.len() as u16));
    record.extend_from_slice(&chlo_hs);
    Ok(ClientHelloBytes {
        record_wire: record,
        handshake_message: chlo_hs,
    })
}

fn write_extension<F: FnOnce(&mut Writer)>(w: &mut Writer, ext_type: u16, body: F) {
    w.push_u16(ext_type);
    let mut inner = Writer::new();
    body(&mut inner);
    let bytes = inner.into_bytes();
    w.push_u16(bytes.len() as u16);
    w.push_slice(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_messages::ClientHelloView;

    #[test]
    fn round_trip_parse_chrome_chlo() {
        let session_id = [0x11u8; SESSION_ID_LEN];
        let random = [0x22u8; TLS_RANDOM_LEN];
        let client_pub = [0x33u8; 32];
        let alpn = [&b"http/1.1"[..]];
        let plan = ClientHelloPlan {
            server_name: "gosuslugi.ru",
            session_id: &session_id,
            client_random: &random,
            client_x25519_public: &client_pub,
            alpn_offer: Some(&alpn),
        };
        let out = build_client_hello(&plan).unwrap();
        // The first byte of the record must be CT_HANDSHAKE (22).
        assert_eq!(out.record_wire[0], CT_HANDSHAKE);
        // Parse the inner CHLO body (strip 5-byte record header + 4-byte handshake header)
        let body = &out.record_wire[5 + 4..];
        let chlo = ClientHelloView::parse(body).unwrap();
        assert_eq!(chlo.session_id.len(), SESSION_ID_LEN);
        assert_eq!(chlo.session_id, &session_id);
        assert_eq!(chlo.sni.as_deref(), Some("gosuslugi.ru"));
        assert!(chlo.offers_tls13());
        let ks = chlo.pick_x25519_key_share().unwrap();
        assert_eq!(ks.key_exchange, &client_pub);
        assert!(chlo.cipher_suites.contains(&TLS_AES_128_GCM_SHA256));
        assert!(chlo.cipher_suites.contains(&TLS_CHACHA20_POLY1305_SHA256));
        assert_eq!(chlo.alpn.len(), 1);
        assert_eq!(chlo.alpn[0], b"http/1.1");
    }
}
