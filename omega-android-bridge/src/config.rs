#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidProfile {
    pub server: String,
    pub device_id: String,
    pub device_token: String,
    pub platform: String,
    pub transport: String,
    /// REALITY parameters are accepted on parse but not yet wired into the
    /// Android native data path (the bridge currently only drives UDP).
    /// They round-trip through `SharedPreferences` so the user can configure
    /// them ahead of the Android REALITY rollout in Phase 7+.
    pub reality_sni: String,
    pub reality_server_pubkey: String,
    pub reality_short_id: String,
    pub reality_fingerprint: String,
}

impl AndroidProfile {
    pub fn parse(
        server: &str,
        device_id: &str,
        device_token: &str,
        platform: &str,
        transport: &str,
    ) -> Result<Self, String> {
        Self::parse_extended(
            server,
            device_id,
            device_token,
            platform,
            transport,
            "",
            "",
            "",
            "",
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn parse_extended(
        server: &str,
        device_id: &str,
        device_token: &str,
        platform: &str,
        transport: &str,
        reality_sni: &str,
        reality_server_pubkey: &str,
        reality_short_id: &str,
        reality_fingerprint: &str,
    ) -> Result<Self, String> {
        let server = non_empty("server", server)?;
        if server.parse::<std::net::SocketAddr>().is_err() {
            return Err("server must be host:port socket address".to_string());
        }

        let device_id = non_empty("device id", device_id)?.to_ascii_lowercase();
        if !looks_like_uuid(&device_id) {
            return Err("device id must be a UUID".to_string());
        }

        let device_token = non_empty("device token", device_token)?.to_ascii_lowercase();
        if device_token.len() != 64 || !device_token.bytes().all(is_hex) {
            return Err("device token must be 64 hex characters".to_string());
        }

        let platform = match platform.trim().to_ascii_lowercase().as_str() {
            "" => "android",
            "android" => "android",
            _ => return Err("platform must be android".to_string()),
        }
        .to_string();

        let transport = match transport.trim().to_ascii_lowercase().as_str() {
            "udp" => "udp",
            "tcp" => "tcp",
            "reality" | "xtls" => "reality",
            "" | "auto" => "auto",
            _ => return Err("transport must be auto, udp, tcp or reality".to_string()),
        }
        .to_string();

        // Phase 6 minimum: persist the REALITY fields verbatim. The Android
        // native bridge will refuse to start a REALITY tunnel in runtime.rs
        // with a clear error until Phase 7+ plumbs a protected-from-VPN TCP
        // socket through `VpnService.protect()`.
        let reality_sni = reality_sni.trim().to_string();
        let reality_server_pubkey = reality_server_pubkey.trim().to_string();
        let reality_short_id = reality_short_id.trim().to_string();
        let reality_fingerprint = if reality_fingerprint.trim().is_empty() {
            "chrome_131".to_string()
        } else {
            reality_fingerprint.trim().to_string()
        };

        // Validate format of REALITY fields if the user actually selected the
        // reality transport (don't burden users who left them blank).
        if transport == "reality" {
            if reality_sni.is_empty() {
                return Err("reality_sni is required when transport=reality".to_string());
            }
            if reality_server_pubkey.is_empty() {
                return Err(
                    "reality_server_pubkey is required when transport=reality".to_string(),
                );
            }
            let decoded = base64_decode_32(&reality_server_pubkey)
                .ok_or_else(|| "reality_server_pubkey must be 32 bytes of base64".to_string())?;
            let _ = decoded;
            if !reality_short_id.is_empty()
                && (reality_short_id.len() != 16 || !reality_short_id.bytes().all(is_hex))
            {
                return Err("reality_short_id must be 16 hex chars (or empty)".to_string());
            }
        }

        Ok(Self {
            server,
            device_id,
            device_token,
            platform,
            transport,
            reality_sni,
            reality_server_pubkey,
            reality_short_id,
            reality_fingerprint,
        })
    }

    pub fn device_id_bytes(&self) -> Result<[u8; 16], String> {
        let compact = self.device_id.replace('-', "");
        parse_hex_array::<16>(&compact, "device id")
    }

    pub fn device_token_bytes(&self) -> Result<[u8; 32], String> {
        parse_hex_array::<32>(&self.device_token, "device token")
    }
}

fn non_empty(label: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(trimmed.to_string())
    }
}

fn looks_like_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for idx in [8, 13, 18, 23] {
        if bytes[idx] != b'-' {
            return false;
        }
    }

    bytes
        .iter()
        .enumerate()
        .all(|(idx, byte)| [8, 13, 18, 23].contains(&idx) || is_hex(*byte))
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn parse_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} has invalid hex length"));
    }

    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let hi = hex_value(bytes[index * 2]).ok_or_else(|| format!("{label} contains non-hex"))?;
        let lo =
            hex_value(bytes[index * 2 + 1]).ok_or_else(|| format!("{label} contains non-hex"))?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn base64_decode_32(raw: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD.decode(raw.trim().as_bytes()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_profile_fields() {
        let config = AndroidProfile::parse(
            "72.56.88.224:51820",
            "550e8400-e29b-41d4-a716-446655440000",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "android",
            "auto",
        )
        .unwrap();

        assert_eq!(config.server, "72.56.88.224:51820");
        assert_eq!(config.platform, "android");
        assert_eq!(config.transport, "auto");
    }

    #[test]
    fn rejects_bad_device_token_length() {
        let err = AndroidProfile::parse(
            "72.56.88.224:51820",
            "550e8400-e29b-41d4-a716-446655440000",
            "abcd",
            "android",
            "auto",
        )
        .unwrap_err();

        assert!(err.contains("device token"));
    }

    #[test]
    fn converts_uuid_and_token_to_protocol_bytes() {
        let config = AndroidProfile::parse(
            "72.56.88.224:51820",
            "550e8400-e29b-41d4-a716-446655440000",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "android",
            "udp",
        )
        .unwrap();

        assert_eq!(
            config.device_id_bytes().unwrap(),
            [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ]
        );
        assert_eq!(config.device_token_bytes().unwrap()[0], 0x00);
        assert_eq!(config.device_token_bytes().unwrap()[31], 0xff);
    }
}
