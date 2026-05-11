//! Shared XTLS REALITY primitives.
//!
//! This crate hosts the protocol-independent half of REALITY support:
//!   * `tls_messages` — TLS 1.3 record/handshake codec.
//!   * `key_schedule` — RFC 8446 §7.1 HKDF schedule for SHA-256 suites.
//!   * `record_layer` — TLS 1.3 AEAD record framing.
//!   * `auth`         — REALITY authentication (`session_id` tag,
//!                      `CertificateVerify` MAC).
//!
//! Higher-level pieces (cert sniffing, listener, server/client handshake
//! orchestration, proxy fallback, transport wrappers) live in the server
//! and client crates, respectively, because they depend on tokio I/O.

pub mod auth;
pub mod handshake_client;
pub mod handshake_server;
pub mod key_schedule;
pub mod record_layer;
pub mod tls_messages;
pub mod utls;
