#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub ok: bool,
    pub handle: u64,
    pub tunnel_ipv4: String,
    pub tunnel_ipv6: Option<String>,
    pub mtu: u16,
    pub dns_servers: Vec<String>,
    pub message: String,
}

impl HandshakeResponse {
    pub fn ok(
        handle: u64,
        tunnel_ipv4: impl Into<String>,
        tunnel_ipv6: Option<String>,
        mtu: u16,
        dns_servers: Vec<String>,
    ) -> Self {
        Self {
            ok: true,
            handle,
            tunnel_ipv4: tunnel_ipv4.into(),
            tunnel_ipv6,
            mtu,
            dns_servers,
            message: String::new(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            handle: 0,
            tunnel_ipv4: String::new(),
            tunnel_ipv6: None,
            mtu: 0,
            dns_servers: Vec::new(),
            message: message.into(),
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":{},\"handle\":{},\"tunnelIpv4\":\"{}\",\"tunnelIpv6\":{},\"mtu\":{},\"dnsServers\":[{}],\"message\":\"{}\"}}",
            if self.ok { "true" } else { "false" },
            self.handle,
            escape_json(&self.tunnel_ipv4),
            self.tunnel_ipv6
                .as_ref()
                .map(|value| format!("\"{}\"", escape_json(value)))
                .unwrap_or_else(|| "null".to_string()),
            self.mtu,
            self.dns_servers
                .iter()
                .map(|value| format!("\"{}\"", escape_json(value)))
                .collect::<Vec<_>>()
                .join(","),
            escape_json(&self.message),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeResult {
    pub ok: bool,
    pub message: String,
}

impl NativeResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":{},\"message\":\"{}\"}}",
            if self.ok { "true" } else { "false" },
            escape_json(&self.message),
        )
    }
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_successful_handshake_response() {
        let json = HandshakeResponse::ok(
            7,
            "10.7.0.2",
            Some("fd70:7::2".to_string()),
            1280,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        )
        .to_json();

        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"handle\":7"));
        assert!(json.contains("\"tunnelIpv4\":\"10.7.0.2\""));
        assert!(json.contains("\"tunnelIpv6\":\"fd70:7::2\""));
        assert!(json.contains("\"dnsServers\":[\"1.1.1.1\",\"8.8.8.8\"]"));
    }

    #[test]
    fn escapes_error_response_message() {
        let json = HandshakeResponse::err("bad \"token\"\nline").to_json();

        assert!(json.contains("bad \\\"token\\\"\\nline"));
    }
}
