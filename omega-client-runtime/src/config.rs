use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use omega_stealth::{MorphingPolicy, PersonaId};

const DEFAULT_DIAGNOSTICS_PATH: &str = "omega-client/state/diagnostics.json";
const DEFAULT_LIFECYCLE_PATH: &str = "omega-client/state/lifecycle.json";
const DEFAULT_CONTROL_PATH: &str = "omega-client/state/runtime-control.json";
const DEFAULT_GAMING_MTU: u16 = 1380;
const DEFAULT_GENERAL_MTU: u16 = 1360;
const DEFAULT_RESTRICTED_MTU: u16 = 1280;
const DEFAULT_UDP_RCVBUF: usize = 8 * 1024 * 1024;
const DEFAULT_UDP_SNDBUF: usize = 8 * 1024 * 1024;
const DEFAULT_HANDSHAKE_ATTEMPTS: u32 = 5;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 1500;
const DEFAULT_HANDSHAKE_BACKOFF_MS: u64 = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
            "general" | "internet" | "default" | "general_internet" => Self::GeneralInternet,
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

    pub fn label(self) -> &'static str {
        match self {
            Self::Gaming => "gaming",
            Self::GeneralInternet => "general_internet",
            Self::RestrictedFallback => "restricted_fallback",
        }
    }
}

fn default_morphing_policy(profile: ConnectionProfile) -> MorphingPolicy {
    match profile {
        ConnectionProfile::Gaming => MorphingPolicy::Off,
        ConnectionProfile::GeneralInternet => MorphingPolicy::Balanced,
        ConnectionProfile::RestrictedFallback => MorphingPolicy::Full,
    }
}

fn default_persona(profile: ConnectionProfile) -> PersonaId {
    match profile {
        ConnectionProfile::Gaming => PersonaId::Randomized,
        ConnectionProfile::GeneralInternet => PersonaId::QuicLike,
        ConnectionProfile::RestrictedFallback => PersonaId::HostileNetwork,
    }
}

fn morphing_policy_from_env(default: MorphingPolicy) -> MorphingPolicy {
    match std::env::var("OMEGA_MORPHING") {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "full" | "aggressive" => MorphingPolicy::Full,
            "balanced" | "auto" | "reduced" => MorphingPolicy::Balanced,
            "off" | "disabled" | "low_latency" | "low-latency" => MorphingPolicy::Off,
            _ => default,
        },
        Err(_) => default,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    Disabled,
    Passthrough,
}

impl Ipv6Policy {
    fn from_env(default: Self) -> Self {
        match std::env::var("OMEGA_IPV6_POLICY") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "passthrough" | "system" | "direct" => Self::Passthrough,
                "disabled" | "off" | "block" => Self::Disabled,
                _ => default,
            },
            Err(_) => default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub profile: ConnectionProfile,
    pub morphing_policy: MorphingPolicy,
    pub persona: PersonaId,
    pub tunnel_mode: TunnelMode,
    pub dns_policy: DnsPolicy,
    pub ipv6_policy: Ipv6Policy,
    pub requested_mtu: u16,
    pub keepalive_secs: u64,
    pub udp_rcvbuf: usize,
    pub udp_sndbuf: usize,
    pub dns_servers: Vec<String>,
    pub split_routes: Vec<Ipv4Route>,
    pub network_diag: bool,
    pub diagnostics_path: PathBuf,
    pub lifecycle_path: PathBuf,
    pub control_path: PathBuf,
    pub handshake_attempts: u32,
    pub handshake_timeout_ms: u64,
    pub handshake_backoff_ms: u64,
}

impl ClientConfig {
    pub fn from_env() -> Self {
        let profile = ConnectionProfile::from_env();
        let morphing_policy = morphing_policy_from_env(default_morphing_policy(profile));
        let persona = PersonaId::from_env(default_persona(profile));

        let mut tunnel_mode = TunnelMode::from_env();
        let split_routes = std::env::var("OMEGA_SPLIT_ROUTES")
            .map(|value| Ipv4Route::parse_list(&value))
            .unwrap_or_default();
        if matches!(tunnel_mode, TunnelMode::Split) && split_routes.is_empty() {
            tracing::warn!(
                "OMEGA_TUNNEL_MODE=split was requested without OMEGA_SPLIT_ROUTES; falling back to full tunnel"
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
        let lifecycle_path = std::env::var("OMEGA_LIFECYCLE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_LIFECYCLE_PATH));
        let control_path = std::env::var("OMEGA_CONTROL_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONTROL_PATH));

        Self {
            profile,
            morphing_policy,
            persona,
            tunnel_mode,
            dns_policy: DnsPolicy::from_env(dns_policy_default),
            ipv6_policy: Ipv6Policy::from_env(ipv6_policy_default),
            requested_mtu,
            keepalive_secs,
            udp_rcvbuf,
            udp_sndbuf,
            dns_servers,
            split_routes,
            network_diag: env_bool("OMEGA_NETWORK_DIAG", true),
            diagnostics_path,
            lifecycle_path,
            control_path,
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
}

pub fn env_bool(name: &str, default: bool) -> bool {
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
    let mut servers = Vec::new();

    for item in configured
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if item.parse::<Ipv4Addr>().is_ok() {
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
