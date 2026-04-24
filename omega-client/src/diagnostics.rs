use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::config::ClientConfig;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpCheckStatus {
    Pending,
    Passed {
        target: String,
        responder: String,
        checked_at_ms: u64,
    },
    Failed {
        reason: String,
        checked_at_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientDiagnosticsSnapshot {
    pub status: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub server_endpoint: String,
    pub device_name: String,
    pub platform: String,
    pub profile: crate::config::ConnectionProfile,
    pub morphing_policy: crate::config::MorphingPolicy,
    pub tunnel_mode: crate::config::TunnelMode,
    pub dns_policy: crate::config::DnsPolicy,
    pub ipv6_policy: crate::config::Ipv6Policy,
    pub requested_mtu: u16,
    pub negotiated_mtu: Option<u16>,
    pub keepalive_secs: u64,
    pub udp_rcvbuf: usize,
    pub udp_sndbuf: usize,
    pub dns_servers: Vec<String>,
    pub split_routes: Vec<String>,
    pub handshake_attempts: u32,
    pub handshake_timeout_ms: u64,
    pub handshake_backoff_ms: u64,
    pub handshake_rtt_ms: Option<u64>,
    pub interface_name: Option<String>,
    pub tunnel_ip: Option<String>,
    pub tunnel_ipv6: Option<String>,
    pub udp_dns_check: UdpCheckStatus,
    pub estimated_rx_loss_ratio: f64,
    pub estimated_rx_loss_percent: f64,
    pub arq_rtt_ms: u64,
    pub active_padding_budget: usize,
    pub active_redundancy_extra: u8,
    pub path_quality: String,
    pub suspected_issue: Option<String>,
    pub last_server_packet_ms: Option<u64>,
    pub last_tun_packet_ms: Option<u64>,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    pub retransmits_sent: u64,
}

#[derive(Clone)]
pub struct ClientDiagnostics {
    path: PathBuf,
    snapshot: Arc<Mutex<ClientDiagnosticsSnapshot>>,
}

impl ClientDiagnostics {
    pub fn new(
        path: PathBuf,
        config: &ClientConfig,
        server_endpoint: SocketAddr,
        device_name: &str,
        platform: &str,
    ) -> Self {
        let now = now_ms();
        Self {
            path,
            snapshot: Arc::new(Mutex::new(ClientDiagnosticsSnapshot {
                status: "starting".to_string(),
                started_at_ms: now,
                updated_at_ms: now,
                server_endpoint: server_endpoint.to_string(),
                device_name: device_name.to_string(),
                platform: platform.to_string(),
                profile: config.profile,
                morphing_policy: config.morphing_policy,
                tunnel_mode: config.tunnel_mode,
                dns_policy: config.dns_policy,
                ipv6_policy: config.ipv6_policy,
                requested_mtu: config.requested_mtu,
                negotiated_mtu: None,
                keepalive_secs: config.keepalive_secs,
                udp_rcvbuf: config.udp_rcvbuf,
                udp_sndbuf: config.udp_sndbuf,
                dns_servers: config.dns_servers.clone(),
                split_routes: config
                    .split_routes
                    .iter()
                    .map(|route| route.cidr.clone())
                    .collect(),
                handshake_attempts: config.handshake_attempts,
                handshake_timeout_ms: config.handshake_timeout_ms,
                handshake_backoff_ms: config.handshake_backoff_ms,
                handshake_rtt_ms: None,
                interface_name: None,
                tunnel_ip: None,
                tunnel_ipv6: None,
                udp_dns_check: UdpCheckStatus::Pending,
                estimated_rx_loss_ratio: 0.0,
                estimated_rx_loss_percent: 0.0,
                arq_rtt_ms: 350,
                active_padding_budget: config.morphing_policy.padding_budget_cap(),
                active_redundancy_extra: 0,
                path_quality: "starting".to_string(),
                suspected_issue: None,
                last_server_packet_ms: None,
                last_tun_packet_ms: None,
                nacks_sent: 0,
                nacks_received: 0,
                retransmits_sent: 0,
            })),
        }
    }

    pub fn spawn_writer(&self) {
        let path = self.path.clone();
        let snapshot = self.snapshot.clone();
        tokio::spawn(async move {
            if let Some(parent) = path.parent() {
                if let Err(err) = tokio::fs::create_dir_all(parent).await {
                    tracing::warn!(error = %err, path = %path.display(), "failed to create diagnostics directory");
                    return;
                }
            }

            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let payload = {
                    let mut guard = snapshot.lock().unwrap();
                    guard.updated_at_ms = now_ms();
                    match serde_json::to_string_pretty(&*guard) {
                        Ok(json) => json,
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to serialize client diagnostics");
                            continue;
                        }
                    }
                };

                if let Err(err) = tokio::fs::write(&path, payload).await {
                    tracing::warn!(error = %err, path = %path.display(), "failed to write client diagnostics");
                }
            }
        });
    }

    pub fn set_status(&self, status: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.status = status.into();
        });
    }

    pub fn write_now(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let payload = {
            let mut guard = self.snapshot.lock().unwrap();
            guard.updated_at_ms = now_ms();
            serde_json::to_string_pretty(&*guard)?
        };
        std::fs::write(&self.path, payload)?;
        Ok(())
    }

    pub fn set_handshake(
        &self,
        tunnel_ip: std::net::Ipv4Addr,
        tunnel_ipv6: Option<std::net::Ipv6Addr>,
        negotiated_mtu: u16,
        rtt_ms: u64,
    ) {
        self.with_snapshot(|snapshot| {
            snapshot.status = "connected".to_string();
            snapshot.tunnel_ip = Some(tunnel_ip.to_string());
            snapshot.tunnel_ipv6 = tunnel_ipv6.map(|value| value.to_string());
            snapshot.negotiated_mtu = Some(negotiated_mtu);
            snapshot.handshake_rtt_ms = Some(rtt_ms);
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn set_interface_name(&self, interface_name: String) {
        self.with_snapshot(|snapshot| {
            snapshot.interface_name = Some(interface_name);
        });
    }

    pub fn note_server_packet(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.last_server_packet_ms = Some(now_ms());
        });
    }

    pub fn note_tun_packet(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.last_tun_packet_ms = Some(now_ms());
        });
    }

    pub fn record_nack_sent(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.nacks_sent += 1;
        });
    }

    pub fn record_nack_received(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.nacks_received += 1;
        });
    }

    pub fn record_retransmits(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.with_snapshot(|snapshot| {
            snapshot.retransmits_sent += count as u64;
        });
    }

    pub fn udp_check_passed(&self, target: SocketAddr, responder: SocketAddr) {
        self.with_snapshot(|snapshot| {
            snapshot.udp_dns_check = UdpCheckStatus::Passed {
                target: target.to_string(),
                responder: responder.to_string(),
                checked_at_ms: now_ms(),
            };
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn udp_check_failed(&self, reason: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.udp_dns_check = UdpCheckStatus::Failed {
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn update_path_metrics(
        &self,
        loss_ratio: f64,
        arq_rtt_ms: u64,
        padding_budget: usize,
        redundancy_extra: usize,
    ) {
        self.with_snapshot(|snapshot| {
            let loss_ratio = loss_ratio.clamp(0.0, 1.0);
            snapshot.estimated_rx_loss_ratio = loss_ratio;
            snapshot.estimated_rx_loss_percent = loss_ratio * 100.0;
            snapshot.arq_rtt_ms = arq_rtt_ms;
            snapshot.active_padding_budget = padding_budget;
            snapshot.active_redundancy_extra = redundancy_extra.min(u8::MAX as usize) as u8;

            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    fn with_snapshot<F>(&self, f: F)
    where
        F: FnOnce(&mut ClientDiagnosticsSnapshot),
    {
        let mut guard = self.snapshot.lock().unwrap();
        f(&mut guard);
        guard.updated_at_ms = now_ms();
    }
}

fn summarize_path(snapshot: &ClientDiagnosticsSnapshot) -> (String, Option<String>) {
    let loss_percent = snapshot.estimated_rx_loss_percent;
    let handshake_rtt_ms = snapshot.handshake_rtt_ms.unwrap_or(snapshot.arq_rtt_ms);
    let udp_diag_failed = matches!(snapshot.udp_dns_check, UdpCheckStatus::Failed { .. });

    if udp_diag_failed {
        return (
            "critical".to_string(),
            Some(
                "generic UDP inside the tunnel is failing; check server NAT, outbound UDP rules, or upstream filtering"
                    .to_string(),
            ),
        );
    }

    if loss_percent >= 15.0 {
        return (
            "critical".to_string(),
            Some(
                "VPN server is reachable, but the active UDP path is very lossy or rate-limited after the handshake"
                    .to_string(),
            ),
        );
    }

    if loss_percent >= 5.0 {
        return (
            "poor".to_string(),
            Some(
                "latency spikes are likely caused by packet loss/retransmits rather than pure server distance"
                    .to_string(),
            ),
        );
    }

    if handshake_rtt_ms >= 350 {
        return (
            "fair".to_string(),
            Some(
                "base RTT to the VPN server is already high; server location or route length is the likely bottleneck"
                    .to_string(),
            ),
        );
    }

    if handshake_rtt_ms >= 220 || snapshot.arq_rtt_ms >= 300 || snapshot.active_redundancy_extra > 0
    {
        return ("fair".to_string(), None);
    }

    ("good".to_string(), None)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, ConnectionProfile, DnsPolicy, Ipv6Policy, MorphingPolicy, TunnelMode,
    };

    fn test_config(path: PathBuf) -> ClientConfig {
        ClientConfig {
            profile: ConnectionProfile::Gaming,
            morphing_policy: MorphingPolicy::Off,
            tunnel_mode: TunnelMode::Full,
            dns_policy: DnsPolicy::Tunnel,
            ipv6_policy: Ipv6Policy::Tunnel,
            requested_mtu: 1380,
            keepalive_secs: 25,
            udp_rcvbuf: 8 * 1024 * 1024,
            udp_sndbuf: 8 * 1024 * 1024,
            dns_servers: vec!["1.1.1.1".to_string()],
            split_routes: Vec::new(),
            split_routes_v6: Vec::new(),
            network_diag: true,
            diagnostics_path: path,
            handshake_attempts: 5,
            handshake_timeout_ms: 1500,
            handshake_backoff_ms: 500,
        }
    }

    #[test]
    fn write_now_persists_latest_status() {
        let path = std::env::temp_dir().join(format!("omega-client-diag-{}.json", now_ms()));
        let config = test_config(path.clone());
        let diagnostics = ClientDiagnostics::new(
            path.clone(),
            &config,
            "127.0.0.1:443".parse().unwrap(),
            "test-device",
            "windows",
        );

        diagnostics.set_status("routing_failed");
        diagnostics.write_now().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"status\": \"routing_failed\""));

        let _ = std::fs::remove_file(path);
    }
}
