use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use serde::Serialize;

const DEFAULT_DIAGNOSTICS_PATH: &str = "omega-client/state/diagnostics.json";
const DEFAULT_GAMING_MTU: u16 = 1380;
const DEFAULT_GENERAL_MTU: u16 = 1360;
const DEFAULT_RESTRICTED_MTU: u16 = 1280;
const DEFAULT_UDP_RCVBUF: usize = 8 * 1024 * 1024;
const DEFAULT_UDP_SNDBUF: usize = 8 * 1024 * 1024;
const DEFAULT_HANDSHAKE_ATTEMPTS: u32 = 5;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 1500;
const DEFAULT_HANDSHAKE_BACKOFF_MS: u64 = 500;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionProfile {
    Gaming,
    GeneralInternet,
    RestrictedFallback,
}

impl ConnectionProfile {
    pub fn from_env() -> Self {
        match std::env::var("OMEGA_PROFILE")
            .unwrap_or_else(|_| "gaming".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "general" | "internet" | "default" => Self::GeneralInternet,
            "restricted" | "fallback" | "restricted_fallback" | "tcp-fallback" => {
                Self::RestrictedFallback
            }
            _ => Self::Gaming,
        }
    }

    pub fn default_mtu(self) -> u16 {
        match self {
            Self::Gaming => DEFAULT_GAMING_MTU,
            Self::GeneralInternet => DEFAULT_GENERAL_MTU,
            Self::RestrictedFallback => DEFAULT_RESTRICTED_MTU,
        }
    }

    pub fn default_keepalive_secs(self) -> u64 {
        match self {
            Self::Gaming => 25,
            Self::GeneralInternet => 15,
            Self::RestrictedFallback => 10,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingPolicy {
    Full,
    Balanced,
    Off,
}

impl MorphingPolicy {
    fn default_for_profile(profile: ConnectionProfile) -> Self {
        match profile {
            ConnectionProfile::Gaming => Self::Off,
            ConnectionProfile::GeneralInternet => Self::Balanced,
            ConnectionProfile::RestrictedFallback => Self::Full,
        }
    }

    fn from_env(default: Self) -> Self {
        match std::env::var("OMEGA_MORPHING") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "full" | "aggressive" => Self::Full,
                "balanced" | "auto" | "reduced" => Self::Balanced,
                "off" | "disabled" | "low_latency" | "low-latency" => Self::Off,
                _ => default,
            },
            Err(_) => default,
        }
    }

    pub fn padding_budget_cap(self) -> usize {
        match self {
            Self::Full => 256,
            Self::Balanced => 96,
            Self::Off => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    Full,
    Split,
}

impl TunnelMode {
    fn from_env() -> Self {
        match std::env::var("OMEGA_TUNNEL_MODE")
            .unwrap_or_else(|_| "full".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "split" | "split_tunnel" => Self::Split,
            _ => Self::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsPolicy {
    Tunnel,
    System,
}

impl DnsPolicy {
    fn from_env(default: Self) -> Self {
        match std::env::var("OMEGA_DNS_POLICY") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "system" | "local" => Self::System,
                "tunnel" | "vpn" => Self::Tunnel,
                _ => default,
            },
            Err(_) => default,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    Disabled,
    Passthrough,
    Tunnel,
}

impl Ipv6Policy {
    fn from_env(default: Self) -> Self {
        match std::env::var("OMEGA_IPV6_POLICY") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "tunnel" | "vpn" => Self::Tunnel,
                "passthrough" | "system" | "direct" => Self::Passthrough,
                "disabled" | "off" | "block" => Self::Disabled,
                _ => default,
            },
            Err(_) => default,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MtuPolicy {
    Fixed,
    Auto,
}

impl MtuPolicy {
    pub fn from_raw(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "pmtu" | "probe" => Self::Auto,
            _ => Self::Fixed,
        }
    }

    fn from_env(default: Self) -> Self {
        std::env::var("OMEGA_MTU_POLICY")
            .map(|value| Self::from_raw(&value))
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchPolicy {
    Off,
    Soft,
    Strict,
}

impl KillSwitchPolicy {
    pub fn from_raw(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" | "block" => Self::Strict,
            "off" | "disabled" | "0" | "false" => Self::Off,
            _ => Self::Soft,
        }
    }

    fn from_env(default: Self) -> Self {
        std::env::var("OMEGA_KILL_SWITCH")
            .map(|value| Self::from_raw(&value))
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsLeakGuardPolicy {
    Off,
    Warn,
    Strict,
}

impl DnsLeakGuardPolicy {
    pub fn from_raw(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" | "fail" => Self::Strict,
            "off" | "disabled" | "0" | "false" => Self::Off,
            _ => Self::Warn,
        }
    }

    fn from_env(default: Self) -> Self {
        std::env::var("OMEGA_DNS_LEAK_GUARD")
            .map(|value| Self::from_raw(&value))
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportPolicy {
    Udp,
    Tcp,
    Reality,
    Auto,
}

impl TransportPolicy {
    pub fn from_raw(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" | "tcp_fallback" | "tcp-fallback" => Self::Tcp,
            "reality" | "xtls" => Self::Reality,
            "auto" | "fallback" => Self::Auto,
            _ => Self::Udp,
        }
    }

    pub fn from_env(default: Self) -> Self {
        std::env::var("OMEGA_TRANSPORT")
            .map(|value| Self::from_raw(&value))
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Route {
    pub cidr: String,
    pub destination: String,
    pub prefix: u8,
    pub netmask: String,
}

impl Ipv4Route {
    pub fn parse_list(raw: &str) -> Vec<Self> {
        raw.split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter_map(|value| match Self::parse(value) {
                Ok(route) => Some(route),
                Err(err) => {
                    tracing::warn!(value, error = %err, "ignoring invalid OMEGA_SPLIT_ROUTES entry");
                    None
                }
            })
            .collect()
    }

    fn parse(raw: &str) -> anyhow::Result<Self> {
        let (ip_raw, prefix_raw) = raw
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("missing CIDR prefix"))?;
        let ip: Ipv4Addr = ip_raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv4 network"))?;
        let prefix: u8 = prefix_raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length"))?;
        if prefix > 32 {
            return Err(anyhow::anyhow!("prefix must be <= 32"));
        }

        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let destination = Ipv4Addr::from(u32::from(ip) & mask);

        Ok(Self {
            cidr: format!("{destination}/{prefix}"),
            destination: destination.to_string(),
            prefix,
            netmask: Ipv4Addr::from(mask).to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv6Route {
    pub cidr: String,
    pub destination: String,
    pub prefix: u8,
}

impl Ipv6Route {
    pub fn parse_list(raw: &str) -> Vec<Self> {
        raw.split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter_map(|value| match Self::parse(value) {
                Ok(route) => Some(route),
                Err(err) => {
                    tracing::warn!(
                        value,
                        error = %err,
                        "ignoring invalid OMEGA_SPLIT_ROUTES_V6 entry"
                    );
                    None
                }
            })
            .collect()
    }

    fn parse(raw: &str) -> anyhow::Result<Self> {
        let (ip_raw, prefix_raw) = raw
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("missing CIDR prefix"))?;
        let ip: Ipv6Addr = ip_raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv6 network"))?;
        let prefix: u8 = prefix_raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length"))?;
        if prefix > 128 {
            return Err(anyhow::anyhow!("prefix must be <= 128"));
        }

        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let destination = Ipv6Addr::from(u128::from(ip) & mask);

        Ok(Self {
            cidr: format!("{destination}/{prefix}"),
            destination: destination.to_string(),
            prefix,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub profile: ConnectionProfile,
    pub morphing_policy: MorphingPolicy,
    pub tunnel_mode: TunnelMode,
    pub dns_policy: DnsPolicy,
    pub ipv6_policy: Ipv6Policy,
    pub mtu_policy: MtuPolicy,
    pub transport_policy: TransportPolicy,
    pub kill_switch_policy: KillSwitchPolicy,
    pub dns_leak_guard_policy: DnsLeakGuardPolicy,
    pub requested_mtu: u16,
    pub mtu_probe_timeout_ms: u64,
    pub keepalive_secs: u64,
    pub udp_rcvbuf: usize,
    pub udp_sndbuf: usize,
    pub dns_servers: Vec<String>,
    pub split_routes: Vec<Ipv4Route>,
    pub split_routes_v6: Vec<Ipv6Route>,
    pub network_diag: bool,
    pub diagnostics_path: PathBuf,
    pub handshake_attempts: u32,
    pub handshake_timeout_ms: u64,
    pub handshake_backoff_ms: u64,
}

impl ClientConfig {
    pub fn from_env() -> Self {
        let profile = ConnectionProfile::from_env();
        let morphing_policy =
            MorphingPolicy::from_env(MorphingPolicy::default_for_profile(profile));

        let mut tunnel_mode = TunnelMode::from_env();
        let split_routes = std::env::var("OMEGA_SPLIT_ROUTES")
            .map(|value| Ipv4Route::parse_list(&value))
            .unwrap_or_default();
        let split_routes_v6 = std::env::var("OMEGA_SPLIT_ROUTES_V6")
            .map(|value| Ipv6Route::parse_list(&value))
            .unwrap_or_default();
        if matches!(tunnel_mode, TunnelMode::Split)
            && split_routes.is_empty()
            && split_routes_v6.is_empty()
        {
            tracing::warn!(
                "OMEGA_TUNNEL_MODE=split was requested without OMEGA_SPLIT_ROUTES or OMEGA_SPLIT_ROUTES_V6; falling back to full tunnel"
            );
            tunnel_mode = TunnelMode::Full;
        }

        let dns_policy_default = match tunnel_mode {
            TunnelMode::Full => DnsPolicy::Tunnel,
            TunnelMode::Split => DnsPolicy::System,
        };
        let ipv6_policy_default = match tunnel_mode {
            TunnelMode::Full => Ipv6Policy::Disabled,
            TunnelMode::Split => Ipv6Policy::Passthrough,
        };

        let requested_mtu = std::env::var("OMEGA_TUN_MTU")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .map(|value| value.clamp(1200, 1420))
            .unwrap_or_else(|| profile.default_mtu());
        let mtu_probe_timeout_ms = std::env::var("OMEGA_MTU_PROBE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(450)
            .clamp(150, 2000);
        let keepalive_secs = std::env::var("OMEGA_KEEPALIVE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| profile.default_keepalive_secs())
            .max(5);
        let udp_rcvbuf = env_usize("OMEGA_UDP_RCVBUF", DEFAULT_UDP_RCVBUF).max(262_144);
        let udp_sndbuf = env_usize("OMEGA_UDP_SNDBUF", DEFAULT_UDP_SNDBUF).max(262_144);
        let handshake_attempts = std::env::var("OMEGA_HANDSHAKE_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_HANDSHAKE_ATTEMPTS)
            .max(1);
        let handshake_timeout_ms = std::env::var("OMEGA_HANDSHAKE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_MS)
            .max(250);
        let handshake_backoff_ms = std::env::var("OMEGA_HANDSHAKE_BACKOFF_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HANDSHAKE_BACKOFF_MS)
            .max(100);

        let dns_servers = parse_dns_servers();
        let diagnostics_path = std::env::var("OMEGA_DIAGNOSTICS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_DIAGNOSTICS_PATH));

        Self {
            profile,
            morphing_policy,
            tunnel_mode,
            dns_policy: DnsPolicy::from_env(dns_policy_default),
            ipv6_policy: Ipv6Policy::from_env(ipv6_policy_default),
            mtu_policy: MtuPolicy::from_env(MtuPolicy::Auto),
            transport_policy: TransportPolicy::from_env(TransportPolicy::Udp),
            kill_switch_policy: KillSwitchPolicy::from_env(KillSwitchPolicy::Soft),
            dns_leak_guard_policy: DnsLeakGuardPolicy::from_env(DnsLeakGuardPolicy::Warn),
            requested_mtu,
            mtu_probe_timeout_ms,
            keepalive_secs,
            udp_rcvbuf,
            udp_sndbuf,
            dns_servers,
            split_routes,
            split_routes_v6,
            network_diag: env_bool("OMEGA_NETWORK_DIAG", true),
            diagnostics_path,
            handshake_attempts,
            handshake_timeout_ms,
            handshake_backoff_ms,
        }
    }

    pub fn should_set_tunnel_dns(&self) -> bool {
        matches!(self.dns_policy, DnsPolicy::Tunnel)
    }

    pub fn should_disable_ipv6(&self) -> bool {
        matches!(self.ipv6_policy, Ipv6Policy::Disabled)
    }

    pub fn should_tunnel_ipv6(&self) -> bool {
        matches!(self.ipv6_policy, Ipv6Policy::Tunnel)
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_dns_servers() -> Vec<String> {
    let configured =
        std::env::var("OMEGA_DNS_SERVERS").unwrap_or_else(|_| "1.1.1.1,8.8.8.8".to_string());
    parse_dns_servers_from(&configured)
}

fn parse_dns_servers_from(configured: &str) -> Vec<String> {
    let mut servers = Vec::new();

    for item in configured
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if item.parse::<IpAddr>().is_ok() {
            servers.push(item.to_string());
        } else {
            tracing::warn!(value = %item, "ignoring invalid OMEGA_DNS_SERVERS entry");
        }
    }

    if servers.is_empty() {
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
    } else {
        servers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv6_split_routes() {
        let routes = Ipv6Route::parse_list("fd70:7:100::/64,2001:db8::/32");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].cidr, "fd70:7:100::/64");
        assert_eq!(routes[1].cidr, "2001:db8::/32");
    }

    #[test]
    fn accepts_ipv6_dns_servers() {
        let servers = parse_dns_servers_from("1.1.1.1,2606:4700:4700::1111");

        assert_eq!(
            servers,
            vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()]
        );
    }

    #[test]
    fn parses_reliability_policies() {
        assert!(matches!(MtuPolicy::from_raw("auto"), MtuPolicy::Auto));
        assert!(matches!(MtuPolicy::from_raw("fixed"), MtuPolicy::Fixed));
        assert!(matches!(
            KillSwitchPolicy::from_raw("strict"),
            KillSwitchPolicy::Strict
        ));
        assert!(matches!(
            DnsLeakGuardPolicy::from_raw("warn"),
            DnsLeakGuardPolicy::Warn
        ));
        assert!(matches!(
            TransportPolicy::from_raw("auto"),
            TransportPolicy::Auto
        ));
        assert!(matches!(
            TransportPolicy::from_raw("tcp"),
            TransportPolicy::Tcp
        ));
    }
}
