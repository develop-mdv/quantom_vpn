//! Minimal TLS 1.3 message codec for the REALITY transport.
//!
//! We do **not** implement the full TLS 1.3 state machine here — only the
//! subset of message parsing and construction that REALITY needs:
//!   * Parse a Chrome-style `ClientHello` enough to extract `session_id`,
//!     `cipher_suites`, the `key_share` (X25519 entry) and the SNI.
//!   * Build `ServerHello`, `EncryptedExtensions`, `Certificate`,
//!     `CertificateVerify`, `Finished` handshake messages.
//!   * Wrap arbitrary fragments in `TLSPlaintext` / `TLSCiphertext` records.
//!
//! Everything else (PSK resumption, 0-RTT, post-handshake auth, etc.) is
//! intentionally out of scope. Anything we do not understand inside an
//! extension is preserved as opaque bytes — we never re-encode an extension
//! we do not need to look at.

use anyhow::{anyhow, bail, Context, Result};

// -----------------------------------------------------------------------------
// Protocol constants
// -----------------------------------------------------------------------------

pub const TLS_VERSION_LEGACY: u16 = 0x0303; // TLS 1.2 — used for legacy_version
pub const TLS_VERSION_13: u16 = 0x0304;

// Record-layer ContentType
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

// HandshakeType
pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;

// Extension types
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_KEY_SHARE: u16 = 0x0033;

// Cipher suites
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// Named groups
pub const NG_X25519: u16 = 0x001d;
pub const NG_SECP256R1: u16 = 0x0017;

// Signature schemes
pub const SS_ED25519: u16 = 0x0807;
pub const SS_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SS_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

// Random length in Hello messages
pub const TLS_RANDOM_LEN: usize = 32;

// Maximum TLS record fragment length (RFC 8446 §5.1)
pub const TLS_MAX_RECORD_PLAINTEXT: usize = 16_384;
pub const TLS_MAX_RECORD_CIPHERTEXT: usize = TLS_MAX_RECORD_PLAINTEXT + 256;

// -----------------------------------------------------------------------------
// Reader (deserialization helper)
// -----------------------------------------------------------------------------

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("short read: need {n}, have {}", self.data.len() - self.pos);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Result<u32> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// Read an opaque vector with an `N`-byte big-endian length prefix.
    pub fn vec_u8(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    pub fn vec_u16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    pub fn vec_u24(&mut self) -> Result<&'a [u8]> {
        let len = self.u24()? as usize;
        self.take(len)
    }
}

// -----------------------------------------------------------------------------
// Writer (serialization helper)
// -----------------------------------------------------------------------------

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn push_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn push_u24(&mut self, v: u32) {
        let b = v.to_be_bytes();
        self.buf.extend_from_slice(&b[1..4]);
    }

    pub fn push_slice(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Append a variable-length vector with a `u8` big-endian length prefix.
    /// `body` writes the body; we measure and backfill the length.
    pub fn vec_u8<F: FnOnce(&mut Writer)>(&mut self, body: F) -> Result<()> {
        let len_pos = self.buf.len();
        self.buf.push(0);
        body(self);
        let body_len = self.buf.len() - len_pos - 1;
        if body_len > u8::MAX as usize {
            bail!("vector body too large for u8 length: {body_len}");
        }
        self.buf[len_pos] = body_len as u8;
        Ok(())
    }

    pub fn vec_u16<F: FnOnce(&mut Writer)>(&mut self, body: F) -> Result<()> {
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        body(self);
        let body_len = self.buf.len() - len_pos - 2;
        if body_len > u16::MAX as usize {
            bail!("vector body too large for u16 length: {body_len}");
        }
        let be = (body_len as u16).to_be_bytes();
        self.buf[len_pos] = be[0];
        self.buf[len_pos + 1] = be[1];
        Ok(())
    }

    pub fn vec_u24<F: FnOnce(&mut Writer)>(&mut self, body: F) -> Result<()> {
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        body(self);
        let body_len = self.buf.len() - len_pos - 3;
        if body_len > 0xFF_FFFF {
            bail!("vector body too large for u24 length: {body_len}");
        }
        let be = (body_len as u32).to_be_bytes();
        self.buf[len_pos] = be[1];
        self.buf[len_pos + 1] = be[2];
        self.buf[len_pos + 2] = be[3];
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

// -----------------------------------------------------------------------------
// ClientHello view (zero-copy parser over the input bytes)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KeyShareEntry<'a> {
    pub group: u16,
    pub key_exchange: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ClientHelloView<'a> {
    pub legacy_version: u16,
    pub random: [u8; TLS_RANDOM_LEN],
    pub session_id: &'a [u8],
    pub cipher_suites: Vec<u16>,
    pub compression_methods: &'a [u8],
    pub extensions_raw: &'a [u8],

    // Parsed extensions (None if absent)
    pub sni: Option<String>,
    pub supported_versions: Vec<u16>,
    pub key_shares: Vec<KeyShareEntry<'a>>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<&'a [u8]>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub has_pre_shared_key: bool,
}

impl<'a> ClientHelloView<'a> {
    /// Parse a `ClientHello` *handshake body* (i.e. the bytes after the
    /// `msg_type` (1B) + `length` (3B) handshake header). The TLS record
    /// outer framing and handshake header MUST be stripped before calling.
    pub fn parse(body: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16().context("CHLO legacy_version")?;

        let random_bytes = r.take(TLS_RANDOM_LEN).context("CHLO random")?;
        let mut random = [0u8; TLS_RANDOM_LEN];
        random.copy_from_slice(random_bytes);

        let session_id = r.vec_u8().context("CHLO session_id")?;
        if session_id.len() > 32 {
            bail!("CHLO session_id too long: {}", session_id.len());
        }

        let cipher_suites_raw = r.vec_u16().context("CHLO cipher_suites")?;
        if cipher_suites_raw.len() % 2 != 0 {
            bail!("CHLO cipher_suites length not multiple of 2");
        }
        let mut cipher_suites = Vec::with_capacity(cipher_suites_raw.len() / 2);
        for chunk in cipher_suites_raw.chunks_exact(2) {
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        let compression_methods = r.vec_u8().context("CHLO compression_methods")?;

        let extensions_raw = r.vec_u16().context("CHLO extensions")?;

        let mut view = Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions_raw,
            sni: None,
            supported_versions: Vec::new(),
            key_shares: Vec::new(),
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            has_pre_shared_key: false,
        };
        view.parse_extensions(extensions_raw)?;
        Ok(view)
    }

    fn parse_extensions(&mut self, raw: &'a [u8]) -> Result<()> {
        let mut r = Reader::new(raw);
        while !r.is_empty() {
            let ext_type = r.u16().context("extension type")?;
            let ext_data = r.vec_u16().context("extension data")?;
            match ext_type {
                EXT_SERVER_NAME => self.sni = parse_sni(ext_data)?,
                EXT_SUPPORTED_VERSIONS => {
                    self.supported_versions = parse_u16_vec_u8(ext_data)?;
                }
                EXT_KEY_SHARE => self.key_shares = parse_key_shares(ext_data)?,
                EXT_SUPPORTED_GROUPS => {
                    self.supported_groups = parse_u16_vec_u16(ext_data)?;
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    self.signature_algorithms = parse_u16_vec_u16(ext_data)?;
                }
                EXT_ALPN => self.alpn = parse_alpn(ext_data)?,
                EXT_PSK_KEY_EXCHANGE_MODES => {
                    self.psk_key_exchange_modes = parse_u8_vec_u8(ext_data)?;
                }
                EXT_PRE_SHARED_KEY => self.has_pre_shared_key = true,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn pick_x25519_key_share(&self) -> Option<&KeyShareEntry<'a>> {
        self.key_shares.iter().find(|k| k.group == NG_X25519)
    }

    pub fn offers_cipher_suite(&self, suite: u16) -> bool {
        self.cipher_suites.contains(&suite)
    }

    pub fn offers_tls13(&self) -> bool {
        self.supported_versions.contains(&TLS_VERSION_13)
    }
}

fn parse_sni(raw: &[u8]) -> Result<Option<String>> {
    let mut r = Reader::new(raw);
    let list = r.vec_u16().context("server_name list")?;
    let mut lr = Reader::new(list);
    while !lr.is_empty() {
        let name_type = lr.u8().context("name_type")?;
        let name = lr.vec_u16().context("HostName")?;
        if name_type == 0 {
            return Ok(Some(
                std::str::from_utf8(name)
                    .map_err(|_| anyhow!("SNI HostName is not valid UTF-8"))?
                    .to_ascii_lowercase(),
            ));
        }
    }
    Ok(None)
}

fn parse_u16_vec_u8(raw: &[u8]) -> Result<Vec<u16>> {
    let mut r = Reader::new(raw);
    let inner = r.vec_u8().context("u16-vector")?;
    if inner.len() % 2 != 0 {
        bail!("u16-vector length not even");
    }
    Ok(inner
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn parse_u16_vec_u16(raw: &[u8]) -> Result<Vec<u16>> {
    let mut r = Reader::new(raw);
    let inner = r.vec_u16().context("u16-vector(u16)")?;
    if inner.len() % 2 != 0 {
        bail!("u16-vector(u16) length not even");
    }
    Ok(inner
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn parse_u8_vec_u8(raw: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(raw);
    let inner = r.vec_u8().context("u8-vector")?;
    Ok(inner.to_vec())
}

fn parse_key_shares(raw: &[u8]) -> Result<Vec<KeyShareEntry<'_>>> {
    let mut r = Reader::new(raw);
    let list = r.vec_u16().context("KeyShare list")?;
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let group = lr.u16().context("KeyShareEntry.group")?;
        let kx = lr.vec_u16().context("KeyShareEntry.key_exchange")?;
        out.push(KeyShareEntry {
            group,
            key_exchange: kx,
        });
    }
    Ok(out)
}

fn parse_alpn(raw: &[u8]) -> Result<Vec<&[u8]>> {
    let mut r = Reader::new(raw);
    let list = r.vec_u16().context("ALPN list")?;
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while !lr.is_empty() {
        out.push(lr.vec_u8().context("ALPN entry")?);
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// ServerHello builder
// -----------------------------------------------------------------------------

pub struct ServerHelloBuilder<'a> {
    pub legacy_version: u16,
    pub random: [u8; TLS_RANDOM_LEN],
    pub legacy_session_id_echo: &'a [u8],
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub selected_group: u16,
    pub key_share: &'a [u8],
    pub negotiated_version: u16, // for supported_versions extension
}

impl<'a> ServerHelloBuilder<'a> {
    /// Encode the *handshake body* of a `ServerHello` (i.e. without the
    /// `msg_type`+`length` handshake header and without the record header).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::with_capacity(128);
        w.push_u16(self.legacy_version);
        w.push_slice(&self.random);
        w.vec_u8(|w| w.push_slice(self.legacy_session_id_echo))?;
        w.push_u16(self.cipher_suite);
        w.push_u8(self.legacy_compression_method);

        // extensions
        w.vec_u16(|w| {
            // supported_versions extension (RFC 8446 §4.2.1)
            write_extension(w, EXT_SUPPORTED_VERSIONS, |w| {
                w.push_u16(self.negotiated_version);
                Ok(())
            })
            .expect("supported_versions write");

            // key_share extension (server variant — single entry, no list length)
            write_extension(w, EXT_KEY_SHARE, |w| {
                w.push_u16(self.selected_group);
                w.vec_u16(|w| w.push_slice(self.key_share))?;
                Ok(())
            })
            .expect("key_share write");
        })?;

        Ok(w.into_bytes())
    }
}

fn write_extension<F: FnOnce(&mut Writer) -> Result<()>>(
    w: &mut Writer,
    ext_type: u16,
    body: F,
) -> Result<()> {
    w.push_u16(ext_type);
    let mut inner = Writer::new();
    body(&mut inner)?;
    let bytes = inner.into_bytes();
    if bytes.len() > u16::MAX as usize {
        bail!("extension body too large: {}", bytes.len());
    }
    w.push_u16(bytes.len() as u16);
    w.push_slice(&bytes);
    Ok(())
}

// -----------------------------------------------------------------------------
// EncryptedExtensions / Certificate / CertificateVerify / Finished builders
// -----------------------------------------------------------------------------

pub fn build_encrypted_extensions(alpn: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut w = Writer::with_capacity(32);
    w.vec_u16(|w| {
        if let Some(proto) = alpn {
            write_extension(w, EXT_ALPN, |w| {
                w.vec_u16(|w| {
                    w.vec_u8(|w| w.push_slice(proto)).expect("ALPN entry");
                })
                .expect("ALPN list");
                Ok(())
            })
            .expect("ALPN ext");
        }
    })?;
    Ok(w.into_bytes())
}

pub fn build_certificate(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut w = Writer::with_capacity(leaf_der.len() + 64);
    // certificate_request_context (server: empty)
    w.vec_u8(|_| {})?;
    // certificate_list
    w.vec_u24(|w| {
        // First entry: leaf
        write_cert_entry(w, leaf_der).expect("leaf entry");
        for entry in chain_der {
            write_cert_entry(w, entry).expect("chain entry");
        }
    })?;
    Ok(w.into_bytes())
}

fn write_cert_entry(w: &mut Writer, der: &[u8]) -> Result<()> {
    w.vec_u24(|w| w.push_slice(der))?;
    // empty extensions
    w.vec_u16(|_| {})?;
    Ok(())
}

pub fn build_certificate_verify(signature_scheme: u16, signature: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::with_capacity(4 + signature.len());
    w.push_u16(signature_scheme);
    w.vec_u16(|w| w.push_slice(signature))?;
    Ok(w.into_bytes())
}

pub fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    verify_data.to_vec()
}

// -----------------------------------------------------------------------------
// Handshake message wrapper (1B type + 3B length + body)
// -----------------------------------------------------------------------------

pub fn wrap_handshake(msg_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::with_capacity(body.len() + 4);
    w.push_u8(msg_type);
    w.vec_u24(|w| w.push_slice(body))?;
    Ok(w.into_bytes())
}

// -----------------------------------------------------------------------------
// TLS record framing (TLSPlaintext / TLSCiphertext outer header)
// -----------------------------------------------------------------------------

pub fn record_header(content_type: u8, length: u16) -> [u8; 5] {
    let len_be = length.to_be_bytes();
    [
        content_type,
        (TLS_VERSION_LEGACY >> 8) as u8,
        TLS_VERSION_LEGACY as u8,
        len_be[0],
        len_be[1],
    ]
}

pub fn wrap_record(content_type: u8, fragment: &[u8]) -> Result<Vec<u8>> {
    if fragment.len() > u16::MAX as usize {
        bail!("record fragment too large: {}", fragment.len());
    }
    let mut out = Vec::with_capacity(5 + fragment.len());
    out.extend_from_slice(&record_header(content_type, fragment.len() as u16));
    out.extend_from_slice(fragment);
    Ok(out)
}

/// Parse a record header from the beginning of the slice. Returns
/// `(content_type, length, header_bytes)`. Does not consume the fragment.
pub fn parse_record_header(buf: &[u8]) -> Result<(u8, u16, [u8; 5])> {
    if buf.len() < 5 {
        bail!("short record header");
    }
    let ct = buf[0];
    let len = u16::from_be_bytes([buf[3], buf[4]]);
    let mut header = [0u8; 5];
    header.copy_from_slice(&buf[..5]);
    Ok((ct, len, header))
}

/// Async I/O helpers live one layer up (in `listener.rs` / `handshake.rs`).
/// Here we expose blocking buffer-oriented APIs only.

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_chlo_minimal() -> Vec<u8> {
        // Build a minimal but valid CHLO body covering: version, random,
        // empty session_id, two cipher suites, [0] compression, extensions
        // with supported_versions(TLS 1.3) + key_share(x25519:32B) + SNI.
        let mut w = Writer::new();
        w.push_u16(TLS_VERSION_LEGACY);
        let random = [0x11u8; 32];
        w.push_slice(&random);
        // session_id = 32 random bytes
        w.vec_u8(|w| w.push_slice(&[0x22u8; 32])).unwrap();
        // cipher_suites
        w.vec_u16(|w| {
            w.push_u16(TLS_AES_128_GCM_SHA256);
            w.push_u16(TLS_CHACHA20_POLY1305_SHA256);
        })
        .unwrap();
        // compression_methods
        w.vec_u8(|w| w.push_u8(0)).unwrap();
        // extensions
        w.vec_u16(|w| {
            // server_name
            write_extension(w, EXT_SERVER_NAME, |w| {
                w.vec_u16(|w| {
                    w.push_u8(0);
                    w.vec_u16(|w| w.push_slice(b"gosuslugi.ru")).unwrap();
                })
                .unwrap();
                Ok(())
            })
            .unwrap();
            // supported_versions
            write_extension(w, EXT_SUPPORTED_VERSIONS, |w| {
                w.vec_u8(|w| w.push_u16(TLS_VERSION_13)).unwrap();
                Ok(())
            })
            .unwrap();
            // key_share
            write_extension(w, EXT_KEY_SHARE, |w| {
                w.vec_u16(|w| {
                    w.push_u16(NG_X25519);
                    w.vec_u16(|w| w.push_slice(&[0x33u8; 32])).unwrap();
                })
                .unwrap();
                Ok(())
            })
            .unwrap();
        })
        .unwrap();
        w.into_bytes()
    }

    #[test]
    fn parse_minimal_chlo() {
        let body = build_chlo_minimal();
        let chlo = ClientHelloView::parse(&body).unwrap();
        assert_eq!(chlo.legacy_version, TLS_VERSION_LEGACY);
        assert_eq!(chlo.session_id.len(), 32);
        assert_eq!(
            chlo.cipher_suites,
            vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256]
        );
        assert_eq!(chlo.sni.as_deref(), Some("gosuslugi.ru"));
        assert!(chlo.offers_tls13());
        let ks = chlo.pick_x25519_key_share().unwrap();
        assert_eq!(ks.group, NG_X25519);
        assert_eq!(ks.key_exchange.len(), 32);
    }

    #[test]
    fn shlo_round_trip() {
        let random = [0xAAu8; 32];
        let key_share = [0xBBu8; 32];
        let sid = [0x22u8; 32];
        let shlo = ServerHelloBuilder {
            legacy_version: TLS_VERSION_LEGACY,
            random,
            legacy_session_id_echo: &sid,
            cipher_suite: TLS_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            selected_group: NG_X25519,
            key_share: &key_share,
            negotiated_version: TLS_VERSION_13,
        }
        .encode()
        .unwrap();

        // Re-parse as a generic CHLO-ish to spot-check shape: version+random+sid+suite+comp+ext_len
        assert_eq!(&shlo[0..2], &TLS_VERSION_LEGACY.to_be_bytes());
        assert_eq!(&shlo[2..34], &random);
        assert_eq!(shlo[34], 32); // session_id length
        assert_eq!(&shlo[35..67], &sid);
        assert_eq!(&shlo[67..69], &TLS_AES_128_GCM_SHA256.to_be_bytes());
        assert_eq!(shlo[69], 0);
        let ext_len = u16::from_be_bytes([shlo[70], shlo[71]]);
        assert_eq!(shlo.len(), 72 + ext_len as usize);
    }

    #[test]
    fn handshake_wrapper_lengths_match() {
        let body = vec![0xAB; 100];
        let wrapped = wrap_handshake(HS_SERVER_HELLO, &body).unwrap();
        assert_eq!(wrapped[0], HS_SERVER_HELLO);
        assert_eq!(&wrapped[1..4], &[0, 0, 100]);
        assert_eq!(&wrapped[4..], body.as_slice());
    }

    #[test]
    fn record_wrapper_lengths_match() {
        let frag = vec![0xCD; 200];
        let rec = wrap_record(CT_HANDSHAKE, &frag).unwrap();
        assert_eq!(rec[0], CT_HANDSHAKE);
        assert_eq!(&rec[1..3], &TLS_VERSION_LEGACY.to_be_bytes());
        assert_eq!(&rec[3..5], &(200u16).to_be_bytes());
        assert_eq!(&rec[5..], frag.as_slice());
    }

    #[test]
    fn certificate_body_has_correct_length_prefixes() {
        let leaf = vec![0xFF; 300];
        let cert = build_certificate(&leaf, &[]).unwrap();
        // first byte = u8 length of certificate_request_context (0)
        assert_eq!(cert[0], 0);
        // next 3 bytes = u24 length of certificate_list
        let list_len = u32::from_be_bytes([0, cert[1], cert[2], cert[3]]) as usize;
        assert_eq!(list_len, cert.len() - 4);
        // first entry: cert_data length (u24)
        let entry_len = u32::from_be_bytes([0, cert[4], cert[5], cert[6]]) as usize;
        assert_eq!(entry_len, 300);
    }
}
