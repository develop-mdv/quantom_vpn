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
    pub tunnel_mode: crate::config::TunnelMode,
    pub dns_policy: crate::config::DnsPolicy,
    pub ipv6_policy: crate::config::Ipv6Policy,
    pub requested_mtu: u16,
    pub negotiated_mtu: Option<u16>,
    pub keepalive_secs: u64,
    pub dns_servers: Vec<String>,
    pub split_routes: Vec<String>,
    pub handshake_attempts: u32,
    pub handshake_timeout_ms: u64,
    pub handshake_backoff_ms: u64,
    pub handshake_rtt_ms: Option<u64>,
    pub interface_name: Option<String>,
    pub tunnel_ip: Option<String>,
    pub udp_dns_check: UdpCheckStatus,
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
                tunnel_mode: config.tunnel_mode,
                dns_policy: config.dns_policy,
                ipv6_policy: config.ipv6_policy,
                requested_mtu: config.requested_mtu,
                negotiated_mtu: None,
                keepalive_secs: config.keepalive_secs,
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
                udp_dns_check: UdpCheckStatus::Pending,
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

    pub fn set_handshake(&self, tunnel_ip: std::net::Ipv4Addr, negotiated_mtu: u16, rtt_ms: u64) {
        self.with_snapshot(|snapshot| {
            snapshot.status = "connected".to_string();
            snapshot.tunnel_ip = Some(tunnel_ip.to_string());
            snapshot.negotiated_mtu = Some(negotiated_mtu);
            snapshot.handshake_rtt_ms = Some(rtt_ms);
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
        });
    }

    pub fn udp_check_failed(&self, reason: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.udp_dns_check = UdpCheckStatus::Failed {
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
