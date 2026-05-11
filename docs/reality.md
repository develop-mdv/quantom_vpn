# REALITY transport for Omega VPN

REALITY is a third transport for Omega (alongside UDP and framed TCP) that
makes outgoing client connections **indistinguishable from a normal TLS 1.3
session to a trusted Russian-whitelist site** — `gosuslugi.ru`, `vk.com`,
`sberbank.ru`, etc. Active DPI probes that connect directly to our IP also
see exactly that site, because REALITY transparently proxies any non-Omega
client through to the real destination.

This document covers:

  * how the cryptographic scheme works (without owning the real site's
    private key);
  * what to configure on the server and the client;
  * how to pick a masquerade target;
  * Prometheus metrics exposed by the server;
  * known limitations.

## 1. How it works

REALITY embeds 32 bytes of authentication material in the TLS 1.3
`session_id` field of the ClientHello. The server uses these bytes plus the
client's X25519 `key_share` and the server's own long-term X25519 secret to
decide whether the connection is from an authentic Omega client.

```text
auth_key   = X25519(client_ephemeral_secret, server_long_term_pubkey)
           = X25519(server_long_term_secret, client_ephemeral_pubkey)
tag        = HMAC-SHA256(auth_key, "reality-auth" || 0x01 || short_id)[..24]
session_id = short_id (8B) || tag (24B)
```

The leaf certificate handed to the client is a verbatim copy of the real
site's certificate, sniffed once at server boot (and refreshed every
12 hours). The server signs the `CertificateVerify` with a MAC keyed by
`auth_key` instead of the leaf cert's private key — only an Omega client
that knows `server_long_term_pubkey` can verify this MAC.

For DPI the wire looks exactly like TLS 1.3 to the trusted site:

  * **SNI** — the trusted hostname.
  * **Server certificate** — the real cert (valid CA chain, valid SCT).
  * **CertificateVerify** — 64 bytes, indistinguishable in shape from
    Ed25519.
  * **ApplicationData** — encrypted records under AES-128-GCM or
    ChaCha20-Poly1305.

For an unauthenticated stranger (e.g. an `nmap`/`openssl s_client` probe),
the server reads the ClientHello and immediately splices the TCP stream to
the real destination — the connection delivers genuine bytes from the real
site.

## 2. Server setup

### 2.1. Generate a REALITY keypair

```bash
omega-server reality-keygen
# writes state/reality_x25519.key
# prints the base64 public key (give this to clients)
```

The private key never leaves `state/reality_x25519.key`. Distribute the
public key out-of-band to every Omega client (QR code, paste box, support
ticket, etc.).

### 2.2. Environment variables

| Variable                              | Default                         | Purpose                                                                        |
|---------------------------------------|---------------------------------|--------------------------------------------------------------------------------|
| `OMEGA_REALITY_ENABLE`                | `0`                             | `1`/`true`/`yes`/`on` enables the listener                                     |
| `OMEGA_REALITY_BIND`                  | `0.0.0.0:443`                   | TCP bind for the REALITY listener                                              |
| `OMEGA_REALITY_DEST`                  | (required)                      | `host:port` of the real upstream site; defaults to port 443 if `:port` omitted |
| `OMEGA_REALITY_SERVER_NAMES`          | `dest` host                     | Comma-separated list of allowed SNI values                                     |
| `OMEGA_REALITY_PRIVATE_KEY_FILE`      | `state/reality_x25519.key`      | Path to the server X25519 keypair                                              |
| `OMEGA_REALITY_CERT_DIR`              | `state/reality_certs`           | Where sniffed leaf certificates are cached                                     |
| `OMEGA_REALITY_SHORT_IDS`             | empty (wildcard only)           | Comma-separated list of 16-hex-char allowed `short_id` tags                    |
| `OMEGA_REALITY_FINGERPRINT_PROFILE`   | `chrome_131`                    | Used for future strict JA4 validation                                          |
| `OMEGA_REALITY_HANDSHAKE_TIMEOUT_MS`  | `10000`                         | Hard handshake deadline                                                        |

### 2.3. Minimal example

```bash
export OMEGA_REALITY_ENABLE=1
export OMEGA_REALITY_BIND=0.0.0.0:443
export OMEGA_REALITY_DEST=gosuslugi.ru:443
export OMEGA_REALITY_SERVER_NAMES=gosuslugi.ru,www.gosuslugi.ru
./omega-server
```

At boot the server:

  1. Loads or generates `state/reality_x25519.key`.
  2. Sniffs `gosuslugi.ru:443` once, caches the leaf cert.
  3. Starts the TCP listener on `:443`.
  4. Spawns a background task that re-sniffs every 12 hours.

## 3. Client setup

### 3.1. Environment variables

| Variable                              | Default       | Purpose                                                          |
|---------------------------------------|---------------|------------------------------------------------------------------|
| `OMEGA_TRANSPORT`                     | `udp`         | Set to `reality` (or `xtls`)                                     |
| `OMEGA_REALITY_SERVER`                | (required)    | `ip:port` of the Omega server                                    |
| `OMEGA_REALITY_SNI`                   | (required)    | SNI to advertise — must match a server `SERVER_NAMES` entry      |
| `OMEGA_REALITY_SERVER_PUBKEY`         | (required)    | Base64 X25519 server public key (printed by `reality-keygen`)    |
| `OMEGA_REALITY_SHORT_ID`              | empty         | 16-hex-char tag if the server requires one                       |
| `OMEGA_REALITY_FINGERPRINT`           | `chrome_131`  | uTLS profile                                                     |
| `OMEGA_REALITY_HANDSHAKE_TIMEOUT_MS`  | `10000`       | Hard handshake deadline                                          |

### 3.2. Minimal example

```bash
export OMEGA_TRANSPORT=reality
export OMEGA_REALITY_SERVER=203.0.113.10:443
export OMEGA_REALITY_SNI=gosuslugi.ru
export OMEGA_REALITY_SERVER_PUBKEY=nEAvUB4JUya5I2Ypm4Cr4/orVt6PGqm+XXqsuYef/QI=
./omega-client
```

Set `OMEGA_TRANSPORT=auto` to try UDP → framed TCP → REALITY in order; the
client falls back to REALITY only if UDP and TCP both fail.

## 4. Picking a masquerade target

Best targets are popular sites with:

  * a valid public-CA chain and SCT,
  * stable TLS 1.3 server with no aggressive 0-RTT/PSK quirks,
  * persistent client connections (so a long-lived ApplicationData stream
    looks natural).

Concrete picks for the Russian "white list" scenario:

  * **`gosuslugi.ru`** — government, always whitelisted.
  * **`www.mos.ru`** — Moscow gov portal.
  * **`online.sberbank.ru`** — banking; mobile apps hold WebSocket-style
    connections, so long-lived traffic is normal.
  * **`www.pochta.ru`** — Russian Post.
  * **`vk.com`** — social, very large traffic volume.
  * **`e.mail.ru`** — webmail.
  * **`yandex.ru`** — search.

Avoid: anything HTTP/3-only, ECH-mandatory, or that frequently mutates
TLS extensions (some CDNs do this).

## 5. Prometheus metrics

Exposed at the existing metrics bind (`OMEGA_METRICS_BIND`,
`/metrics` endpoint):

| Metric                                                | Type    | Labels                       |
|-------------------------------------------------------|---------|------------------------------|
| `omega_reality_handshakes_total`                      | counter | `verdict=authentic\|foreign` |
| `omega_reality_handshakes_by_short_id_total`          | counter | `short_id`                   |
| `omega_reality_handshake_errors_total`                | counter | `reason`                     |
| `omega_reality_proxy_bytes_total`                     | counter | `direction`                  |
| `omega_reality_active_tunnels`                        | gauge   | —                            |
| `omega_reality_cert_refresh_total`                    | counter | `sni`, `rotated`             |

Alert ideas: spike on `verdict=foreign` (DPI activity), `rotated=true` on
all SNIs in the same hour (upstream rotated certs — Omega is still
healthy, but worth knowing).

## 6. Known limitations

  1. **No browser interoperability.** The REALITY `CertificateVerify` is
     MAC-keyed by `auth_key`, not signed by the leaf cert's private key.
     A normal browser will reject it. This is by design — browsers should
     not reach the Omega listener anyway; if they do, they end up in the
     transparent proxy fallback. `openssl s_client -verify_return_error`
     will see the same error.
  2. **No OCSP stapling.** The real site may staple OCSP; we cannot
     reproduce that signature. We never emit `status_request` in
     `EncryptedExtensions`, so DPI sees a TLS server that just doesn't
     staple — common and benign.
  3. **No ECH.** The Chrome 131 profile we ship does not advertise
     Encrypted Client Hello. If the upstream site requires ECH or future
     Chrome makes ECH default, the JA4 fingerprint will drift.
  4. **No 0-RTT, no session resumption.** Always full handshake. If the
     upstream supports session tickets we don't honour them.
  5. **Certificate Transparency.** The leaf cert we serve has valid SCTs
     because it *is* the real leaf cert. CT auditors will see entries
     for the real site (as expected) and nothing else.
  6. **HTTP/2 ALPN.** We always negotiate `http/1.1`. The real
     `gosuslugi.ru` answers `h2`. A sophisticated DPI that compares ALPN
     across millions of connections could spot this anomaly; consider
     upgrading to `h2` advertising once Phase 6+ wires up proper HTTP/2
     frame mimicry.
  7. **JA3/JA4 drift.** The bundled Chrome 131 profile is a static
     snapshot. If you suspect fingerprint blocking, re-capture a real
     Chrome stable CHLO in Wireshark and update
     `omega-reality/src/utls.rs`.

## 7. Troubleshooting

| Symptom                                                                            | Likely cause                                  | Fix                                                          |
|------------------------------------------------------------------------------------|-----------------------------------------------|--------------------------------------------------------------|
| Client error `REALITY CertificateVerify signature failed`                          | Wrong `OMEGA_REALITY_SERVER_PUBKEY`           | Re-fetch the base64 from the server `reality-keygen` output. |
| All clients go to proxy fallback (`verdict=foreign` only)                          | `short_id` mismatch                           | Server `OMEGA_REALITY_SHORT_IDS` must include the client's.  |
| `cert refresh failed; keeping existing snapshot`                                   | Upstream blocked, transient network error     | Investigate egress firewall; logs return to normal next tick. |
| `server picked unsupported cipher suite 0x...`                                     | Client offered only suites the server refused | Use the bundled uTLS profile; do not edit cipher_suites.     |

## 8. Operating procedure

  1. **Generate REALITY keypair on the server.** Print the public key.
  2. **Distribute the public key** to clients (via the existing onboarding
     channel — connection code, QR, etc.).
  3. **Enable REALITY** on the server (`OMEGA_REALITY_ENABLE=1`) and
     restart.
  4. **Verify** by tailing logs for `reality: cert snapshot ready` for
     every advertised SNI and `reality: listener accepting connections`.
  5. **Test from a client** with `OMEGA_TRANSPORT=reality` and the
     advertised SNI; logs should say
     `reality: TLS 1.3 flight completed`.
  6. **Probe externally** with `curl -k https://your-ip/`. You should
     receive bytes from the real site (or a TLS error from curl due to
     the SNI mismatch — that's still fine, the bytes came from upstream).
