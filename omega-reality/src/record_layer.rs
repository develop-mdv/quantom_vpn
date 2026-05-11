//! TLS 1.3 record framing + AEAD sealing/opening (RFC 8446 §5.2).
//!
//! A record on the wire after handshake-stage keys are active looks like:
//!
//! ```text
//! opaque_type = application_data (23)   1 byte
//! legacy_version = 0x0303               2 bytes
//! length                                2 bytes  (= inner + tag)
//! encrypted_record                      length bytes
//! ```
//!
//! and the encrypted record decodes to a `TLSInnerPlaintext`:
//!
//! ```text
//! content             plaintext bytes
//! real_type           1 byte         (= handshake | application_data | alert)
//! zeros               variable       (optional padding)
//! ```
//!
//! The 12-byte AEAD nonce is `iv XOR (seq_number padded with leading zeros)`,
//! and the AAD is the 5-byte outer record header. The sequence number starts
//! at 0 for each new traffic secret (e.g. handshake keys, application keys,
//! or after a KeyUpdate).

use anyhow::{anyhow, bail, Result};
use ring::aead;

use crate::key_schedule::{CipherSuiteParams, TrafficKeys, TLS13_IV_LEN};
use crate::tls_messages::{
    record_header, CT_APPLICATION_DATA, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
};

pub const AEAD_TAG_LEN: usize = 16;

fn algorithm_for(suite: u16) -> Result<&'static aead::Algorithm> {
    match suite {
        TLS_AES_128_GCM_SHA256 => Ok(&aead::AES_128_GCM),
        TLS_CHACHA20_POLY1305_SHA256 => Ok(&aead::CHACHA20_POLY1305),
        _ => bail!("record_layer: unsupported cipher suite 0x{:04x}", suite),
    }
}

/// Compute the per-record AEAD nonce: `iv XOR (seq padded with leading zeros)`.
fn compute_nonce(iv: &[u8; TLS13_IV_LEN], seq: u64) -> [u8; TLS13_IV_LEN] {
    let mut nonce = *iv;
    let seq_be = seq.to_be_bytes(); // 8 bytes
    // XOR into the *trailing* 8 bytes of the 12-byte iv (RFC 8446 §5.3).
    let off = TLS13_IV_LEN - seq_be.len();
    for (i, b) in seq_be.iter().enumerate() {
        nonce[off + i] ^= b;
    }
    nonce
}

/// One direction of an encrypted record stream (e.g. server → client).
pub struct RecordEncryptor {
    key: aead::LessSafeKey,
    iv: [u8; TLS13_IV_LEN],
    seq: u64,
}

impl RecordEncryptor {
    pub fn new(params: &CipherSuiteParams, traffic_secret: &[u8]) -> Result<Self> {
        let keys = TrafficKeys::derive(traffic_secret, params)?;
        Self::from_keys(params.suite, &keys)
    }

    pub fn from_keys(suite: u16, keys: &TrafficKeys) -> Result<Self> {
        let alg = algorithm_for(suite)?;
        let unbound = aead::UnboundKey::new(alg, &keys.key)
            .map_err(|_| anyhow!("AEAD key length mismatch for suite 0x{:04x}", suite))?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            iv: keys.iv,
            seq: 0,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Seal one record. Returns the full wire bytes (5-byte header + ciphertext + tag).
    ///
    /// The `inner_content_type` is the *real* content type of the plaintext
    /// (e.g. `CT_HANDSHAKE` for a server flight, `CT_APPLICATION_DATA` once we
    /// move to user data). The outer record always has `application_data`
    /// content type, per TLS 1.3.
    pub fn seal_record(
        &mut self,
        inner_content_type: u8,
        plaintext: &[u8],
        padding_zero_bytes: usize,
    ) -> Result<Vec<u8>> {
        // Build the inner plaintext: content || real_type || zeros.
        let inner_len = plaintext
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(padding_zero_bytes))
            .ok_or_else(|| anyhow!("plaintext too large"))?;
        let cipher_len = inner_len.checked_add(AEAD_TAG_LEN).ok_or_else(|| {
            anyhow!("ciphertext length overflow ({inner_len} + tag)")
        })?;
        if cipher_len > u16::MAX as usize {
            bail!("record fragment too large: {cipher_len}");
        }

        let mut buf = Vec::with_capacity(inner_len);
        buf.extend_from_slice(plaintext);
        buf.push(inner_content_type);
        buf.extend(std::iter::repeat(0u8).take(padding_zero_bytes));

        let header = record_header(CT_APPLICATION_DATA, cipher_len as u16);
        let nonce_bytes = compute_nonce(&self.iv, self.seq);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(&header[..]), &mut buf)
            .map_err(|_| anyhow!("AEAD seal failed"))?;
        debug_assert_eq!(buf.len(), cipher_len);

        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("record sequence number overflow (seal)"))?;

        let mut out = Vec::with_capacity(5 + cipher_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(&buf);
        Ok(out)
    }
}

/// One direction of decryption (e.g. client → server reads).
pub struct RecordDecryptor {
    key: aead::LessSafeKey,
    iv: [u8; TLS13_IV_LEN],
    seq: u64,
}

#[derive(Debug, Clone)]
pub struct DecryptedRecord {
    pub content_type: u8,
    pub content: Vec<u8>,
}

impl RecordDecryptor {
    pub fn new(params: &CipherSuiteParams, traffic_secret: &[u8]) -> Result<Self> {
        let keys = TrafficKeys::derive(traffic_secret, params)?;
        Self::from_keys(params.suite, &keys)
    }

    pub fn from_keys(suite: u16, keys: &TrafficKeys) -> Result<Self> {
        let alg = algorithm_for(suite)?;
        let unbound = aead::UnboundKey::new(alg, &keys.key)
            .map_err(|_| anyhow!("AEAD key length mismatch for suite 0x{:04x}", suite))?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            iv: keys.iv,
            seq: 0,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Open one record. `outer_header` is the 5-byte TLSCiphertext header
    /// (used as AAD); `cipher_and_tag` is the encrypted_record bytes
    /// (ciphertext concatenated with the 16-byte tag). On success returns
    /// the inner plaintext's *real* content type and content (padding bytes
    /// already stripped).
    pub fn open_record(
        &mut self,
        outer_header: &[u8; 5],
        cipher_and_tag: &mut Vec<u8>,
    ) -> Result<DecryptedRecord> {
        if outer_header[0] != CT_APPLICATION_DATA {
            bail!(
                "record_layer: expected outer ContentType=application_data, got {}",
                outer_header[0]
            );
        }
        if cipher_and_tag.len() < AEAD_TAG_LEN {
            bail!(
                "record_layer: ciphertext too short ({})",
                cipher_and_tag.len()
            );
        }
        let nonce_bytes = compute_nonce(&self.iv, self.seq);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext = self
            .key
            .open_in_place(nonce, aead::Aad::from(&outer_header[..]), cipher_and_tag)
            .map_err(|_| anyhow!("AEAD open failed (bad tag or wrong key)"))?;

        // Strip trailing zero padding; the last remaining byte is the real type.
        let mut end = plaintext.len();
        while end > 0 && plaintext[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            bail!("record_layer: decrypted record contains only padding");
        }
        let inner_ct = plaintext[end - 1];
        let content = plaintext[..end - 1].to_vec();

        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("record sequence number overflow (open)"))?;

        Ok(DecryptedRecord {
            content_type: inner_ct,
            content,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_schedule::{CipherSuiteParams, TrafficKeys};
    use crate::tls_messages::CT_HANDSHAKE;

    fn make_keys(suite: u16) -> (TrafficKeys, CipherSuiteParams) {
        let params = CipherSuiteParams::for_suite(suite).unwrap();
        let secret = vec![0xABu8; 32];
        let keys = TrafficKeys::derive(&secret, &params).unwrap();
        (keys, params)
    }

    #[test]
    fn round_trip_aes128_gcm() {
        let (keys, params) = make_keys(TLS_AES_128_GCM_SHA256);
        let mut enc = RecordEncryptor::from_keys(params.suite, &keys).unwrap();
        let mut dec = RecordDecryptor::from_keys(params.suite, &keys).unwrap();

        for i in 0..5u32 {
            let plaintext = format!("hello, record #{i}!");
            let wire = enc.seal_record(CT_HANDSHAKE, plaintext.as_bytes(), 0).unwrap();
            let (ct, len, header) =
                crate::tls_messages::parse_record_header(&wire).unwrap();
            assert_eq!(ct, CT_APPLICATION_DATA);
            assert_eq!(len as usize, wire.len() - 5);
            let mut cipher_and_tag = wire[5..].to_vec();
            let opened = dec.open_record(&header, &mut cipher_and_tag).unwrap();
            assert_eq!(opened.content_type, CT_HANDSHAKE);
            assert_eq!(opened.content, plaintext.as_bytes());
        }
        assert_eq!(enc.sequence(), 5);
        assert_eq!(dec.sequence(), 5);
    }

    #[test]
    fn round_trip_chacha20_poly1305() {
        let (keys, params) = make_keys(TLS_CHACHA20_POLY1305_SHA256);
        let mut enc = RecordEncryptor::from_keys(params.suite, &keys).unwrap();
        let mut dec = RecordDecryptor::from_keys(params.suite, &keys).unwrap();
        let plaintext = b"a much longer payload spanning multiple AEAD blocks, just to be safe.";
        let wire = enc
            .seal_record(CT_APPLICATION_DATA, plaintext, 17)
            .unwrap();
        let (_, _, header) =
            crate::tls_messages::parse_record_header(&wire).unwrap();
        let mut cipher_and_tag = wire[5..].to_vec();
        let opened = dec.open_record(&header, &mut cipher_and_tag).unwrap();
        assert_eq!(opened.content_type, CT_APPLICATION_DATA);
        assert_eq!(opened.content, plaintext);
    }

    #[test]
    fn out_of_order_decryption_fails() {
        let (keys, params) = make_keys(TLS_AES_128_GCM_SHA256);
        let mut enc = RecordEncryptor::from_keys(params.suite, &keys).unwrap();
        let mut dec = RecordDecryptor::from_keys(params.suite, &keys).unwrap();

        let w0 = enc.seal_record(CT_HANDSHAKE, b"first", 0).unwrap();
        let w1 = enc.seal_record(CT_HANDSHAKE, b"second", 0).unwrap();

        // Open second before first → wrong nonce → AEAD fails.
        let (_, _, h1) =
            crate::tls_messages::parse_record_header(&w1).unwrap();
        let mut c1 = w1[5..].to_vec();
        assert!(dec.open_record(&h1, &mut c1).is_err());

        // After a failed open, the decryptor's seq is unchanged; opening w0 succeeds.
        // But we mutated c1 (open_in_place); use w0 freshly.
        let (_, _, h0) =
            crate::tls_messages::parse_record_header(&w0).unwrap();
        let mut c0 = w0[5..].to_vec();
        // seq still 0 → matches the first record's nonce
        assert!(dec.open_record(&h0, &mut c0).is_ok());
    }

    #[test]
    fn nonce_xor_xors_only_trailing_8_bytes() {
        let iv = [
            0xAA, 0xBB, 0xCC, 0xDD, // first 4 untouched
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nonce = compute_nonce(&iv, 0x0102030405060708);
        assert_eq!(&nonce[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&nonce[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
