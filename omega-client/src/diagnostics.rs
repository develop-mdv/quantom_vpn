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
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MtuProbeStatus {
    Pending,
    Fixed {
        mtu: u16,
    },
    Selected {
        selected_mtu: u16,
        candidates: Vec<u16>,
        probes_sent: usize,
        checked_at_ms: u64,
    },
    Failed {
        fallback_mtu: u16,
        candidates: Vec<u16>,
        reason: String,
        checked_at_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HealthCheckStatus {
    Pending,
    Skipped { reason: String, checked_at_ms: u64 },
    Passed { target: String, checked_at_ms: u64 },
    Failed { reason: String, checked_at_ms: u64 },
}

#[derive(Debug, Clone, Copy)]
pub enum HealthCheckKind {
    Ipv4Egress,
    Ipv6Egress,
    Dns,
    DnsLeakGuard,
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
    pub transport_policy: crate::config::TransportPolicy,
    pub kill_switch_policy: crate::config::KillSwitchPolicy,
    pub dns_leak_guard_policy: crate::config::DnsLeakGuardPolicy,
    pub requested_mtu: u16,
    pub effective_mtu: u16,
    pub mtu_policy: crate::config::MtuPolicy,
    pub mtu_probe: MtuProbeStatus,
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
    pub ipv4_egress_check: HealthCheckStatus,
    pub ipv6_egress_check: HealthCheckStatus,
    pub dns_check: HealthCheckStatus,
    pub dns_leak_check: HealthCheckStatus,
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
                transport_policy: config.transport_policy,
                kill_switch_policy: config.kill_switch_policy,
                dns_leak_guard_policy: config.dns_leak_guard_policy,
                requested_mtu: config.requested_mtu,
                effective_mtu: config.requested_mtu,
                mtu_policy: config.mtu_policy,
                mtu_probe: MtuProbeStatus::Pending,
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
                ipv4_egress_check: HealthCheckStatus::Pending,
                ipv6_egress_check: HealthCheckStatus::Pending,
                dns_check: HealthCheckStatus::Pending,
                dns_leak_check: HealthCheckStatus::Pending,
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

    pub fn mtu_probe_fixed(&self, mtu: u16) {
        self.with_snapshot(|snapshot| {
            snapshot.effective_mtu = mtu;
            snapshot.mtu_probe = MtuProbeStatus::Fixed { mtu };
        });
    }

    pub fn mtu_probe_selected(&self, selected_mtu: u16, candidates: Vec<u16>, probes_sent: usize) {
        self.with_snapshot(|snapshot| {
            snapshot.effective_mtu = selected_mtu;
            snapshot.mtu_probe = MtuProbeStatus::Selected {
                selected_mtu,
                candidates,
                probes_sent,
                checked_at_ms: now_ms(),
            };
        });
    }

    pub fn mtu_probe_failed(
        &self,
        fallback_mtu: u16,
        candidates: Vec<u16>,
        reason: impl Into<String>,
    ) {
        self.with_snapshot(|snapshot| {
            snapshot.effective_mtu = fallback_mtu;
            snapshot.mtu_probe = MtuProbeStatus::Failed {
                fallback_mtu,
                candidates,
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
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

    pub fn health_check_passed(&self, kind: HealthCheckKind, target: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            *health_slot(snapshot, kind) = HealthCheckStatus::Passed {
                target: target.into(),
                checked_at_ms: now_ms(),
            };
        });
    }

    pub fn health_check_failed(&self, kind: HealthCheckKind, reason: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            *health_slot(snapshot, kind) = HealthCheckStatus::Failed {
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
        });
    }

    pub fn health_check_skipped(&self, kind: HealthCheckKind, reason: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            *health_slot(snapshot, kind) = HealthCheckStatus::Skipped {
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
        });
    }

    pub fn refresh_connection_health(&self, ipv6_required: bool) {
        self.with_snapshot(|snapshot| {
            let required = [
                &snapshot.ipv4_egress_check,
                &snapshot.dns_check,
                &snapshot.dns_leak_check,
            ];
            let required_ok = required.iter().all(|status| {
                matches!(
                    status,
                    HealthCheckStatus::Passed { .. } | HealthCheckStatus::Skipped { .. }
                )
            });
            let ipv6_ok = if ipv6_required {
                matches!(snapshot.ipv6_egress_check, HealthCheckStatus::Passed { .. })
            } else {
                matches!(
                    snapshot.ipv6_egress_check,
                    HealthCheckStatus::Passed { .. } | HealthCheckStatus::Skipped { .. }
                )
            };

            snapshot.status = if required_ok && ipv6_ok {
                "connected_healthy".to_string()
            } else {
                "connected_degraded".to_string()
            };
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

fn health_slot(
    snapshot: &mut ClientDiagnosticsSnapshot,
    kind: HealthCheckKind,
) -> &mut HealthCheckStatus {
    match kind {
        HealthCheckKind::Ipv4Egress => &mut snapshot.ipv4_egress_check,
        HealthCheckKind::Ipv6Egress => &mut snapshot.ipv6_egress_check,
        HealthCheckKind::Dns => &mut snapshot.dns_check,
        HealthCheckKind::DnsLeakGuard => &mut snapshot.dns_leak_check,
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
        ClientConfig, ConnectionProfile, DnsLeakGuardPolicy, DnsPolicy, Ipv6Policy,
        KillSwitchPolicy, MorphingPolicy, MtuPolicy, TransportPolicy, TunnelMode,
    };

    fn test_config(path: PathBuf) -> ClientConfig {
        ClientConfig {
            profile: ConnectionProfile::Gaming,
            morphing_policy: MorphingPolicy::Off,
            tunnel_mode: TunnelMode::Full,
            dns_policy: DnsPolicy::Tunnel,
            ipv6_policy: Ipv6Policy::Tunnel,
            mtu_policy: MtuPolicy::Auto,
            transport_policy: TransportPolicy::Udp,
            kill_switch_policy: KillSwitchPolicy::Soft,
            dns_leak_guard_policy: DnsLeakGuardPolicy::Warn,
            requested_mtu: 1380,
            mtu_probe_timeout_ms: 450,
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

    #[test]
    fn write_now_persists_mtu_probe_result() {
        let path = std::env::temp_dir().join(format!("omega-client-diag-mtu-{}.json", now_ms()));
        let config = test_config(path.clone());
        let diagnostics = ClientDiagnostics::new(
            path.clone(),
            &config,
            "127.0.0.1:443".parse().unwrap(),
            "test-device",
            "windows",
        );

        diagnostics.mtu_probe_selected(1320, vec![1380, 1360, 1320], 2);
        diagnostics.write_now().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"effective_mtu\": 1320"));
        assert!(raw.contains("\"status\": \"selected\""));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn health_checks_drive_connected_status() {
        let path = std::env::temp_dir().join(format!("omega-client-diag-health-{}.json", now_ms()));
        let config = test_config(path.clone());
        let diagnostics = ClientDiagnostics::new(
            path.clone(),
            &config,
            "127.0.0.1:443".parse().unwrap(),
            "test-device",
            "windows",
        );

        diagnostics.health_check_passed(HealthCheckKind::Ipv4Egress, "1.1.1.1:53");
        diagnostics.health_check_passed(HealthCheckKind::Dns, "1.1.1.1:53");
        diagnostics.health_check_skipped(HealthCheckKind::Ipv6Egress, "IPv6 tunnel not requested");
        diagnostics.health_check_passed(HealthCheckKind::DnsLeakGuard, "tunnel DNS assigned");
        diagnostics.refresh_connection_health(false);
        diagnostics.write_now().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"status\": \"connected_healthy\""));
        assert!(raw.contains("\"ipv4_egress_check\""));

        let _ = std::fs::remove_file(path);
    }
}
