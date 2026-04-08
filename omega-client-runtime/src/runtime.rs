use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use omega_core_crypto::SessionKeys;
use omega_stealth::{ChaosPrng, PersonaId, StealthEngine, StealthSnapshot};
use omega_transport::arq::{GapDetector, LossEstimator, RetransmitQueue};
use omega_transport::raptorq_mgr::{
    build_live_fec_frames, FecConfig, FecEncoder, FecState, LiveFecReceiver,
};
use omega_transport::reliability::{ReliabilityController, ReliabilitySnapshot};
use omega_transport::transport_v2::{
    CompletedMessage, TransportConfig, TransportEndpoint, TransportSnapshot,
};

use omega_core_wire::*;
use omega_transport::replay::ReplayFilter;
use tokio::net::UdpSocket;

use crate::config::{env_bool, ClientConfig, MorphingPolicy, TunnelMode};
use crate::diagnostics::ClientDiagnostics;
use crate::handshake::perform_handshake_v2;
use crate::lifecycle::{
    wait_for_runtime_stop, ClientFailureScope, ClientLifecycle, ClientLifecycleState,
};

const DEFAULT_SERVER: &str = "127.0.0.1:51820";
const DEFAULT_TUN_PREFIX: u8 = 16;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const MAX_RETRANSMIT_BURST: usize = 24;
#[allow(dead_code)]
const RETRANSMIT_PACING_US: u64 = 500;
#[allow(dead_code)]
const PADDING_BUDGET_MIN: usize = 0;
#[allow(dead_code)]
const PADDING_RECOVERY_STEP: usize = 24;
#[allow(dead_code)]
const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
#[allow(dead_code)]
const REDUNDANCY_EXTRA_MAX: u8 = 2;
#[allow(dead_code)]
const REDUNDANCY_DECAY_SECS: u64 = 8;
#[allow(dead_code)]
const REDUNDANCY_PACING_US: u64 = 200;

#[allow(dead_code)]
struct ClientState {
    retransmit_queue: RetransmitQueue,
    transport: TransportEndpoint,
    header_protection: HeaderProtectionKey,
    transport_payload_budget: usize,
    keys: Option<SessionKeys>,
    gap_detector: GapDetector,
    loss_estimator: LossEstimator,
    send_seq: u32,
    rtp_seq: u16,
    rtp_timestamp: u32,
    ssrc: u32,
    chaos: ChaosPrng,
    stealth: StealthEngine,
    morphing_policy: MorphingPolicy,
    padding_budget: usize,
    last_padding_adjust: Instant,
    redundancy_extra: u8,
    last_redundancy_adjust: Instant,
    reliability: ReliabilityController,
    live_fec: LiveFecReceiver,
    fec_encoder: FecEncoder,
    fec_state: FecState,
    fec_frames_sent: u64,
    fec_frames_received: u64,
    fec_recoveries: u64,
    duplicate_packets_sent: u64,
    suppressed_duplicates: u64,
    loss_est_seq: u32,
    loss_est_init: bool,
}

#[allow(dead_code)]
impl ClientState {
    fn new(
        ssrc: u32,
        chaos_seed: u64,
        morphing_policy: MorphingPolicy,
        persona: PersonaId,
    ) -> Self {
        let fec_config = FecConfig::default();
        let fec_state = FecState::new(fec_config);
        let fec_encoder = FecEncoder::new(fec_config);
        let stealth = StealthEngine::new(persona);
        let max_cover_budget = stealth.max_cover_budget_bytes();

        Self {
            retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
            transport: TransportEndpoint::new(
                ConnectionId([0u8; 8]),
                [0u8; 32],
                TransportConfig::default(),
            ),
            header_protection: HeaderProtectionKey::derive(&[0u8; 32]),
            transport_payload_budget: TransportConfig::default().max_datagram_payload,
            keys: None,
            stealth,
            gap_detector: GapDetector::new(),
            loss_estimator: LossEstimator::new(),
            send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            chaos: ChaosPrng::new(chaos_seed),
            morphing_policy,
            padding_budget: morphing_policy.padding_budget_cap().max(max_cover_budget),
            last_padding_adjust: Instant::now(),
            redundancy_extra: 0,
            last_redundancy_adjust: Instant::now(),
            reliability: ReliabilityController::new(),
            live_fec: LiveFecReceiver::new(),
            fec_encoder,
            fec_state,
            fec_frames_sent: 0,
            fec_frames_received: 0,
            fec_recoveries: 0,
            duplicate_packets_sent: 0,
            suppressed_duplicates: 0,
            loss_est_seq: 0,
            loss_est_init: false,
        }
    }

    fn configure_transport(
        &mut self,
        connection_id: ConnectionId,
        transport_secret: [u8; 32],
        header_secret: [u8; 32],
        mtu: u16,
    ) {
        let max_payload = (mtu as usize).saturating_sub(TOTAL_OVERHEAD).max(256);
        self.transport_payload_budget = max_payload;
        self.header_protection = HeaderProtectionKey::derive(&header_secret);
        self.transport = TransportEndpoint::new(
            connection_id,
            transport_secret,
            TransportConfig {
                max_datagram_payload: max_payload,
                ..TransportConfig::default()
            },
        );
    }
    fn install_session_keys(&mut self, keys: SessionKeys) {
        self.keys = Some(keys);
    }
    fn current_padding_budget(&mut self) -> usize {
        let padding_cap = self
            .morphing_policy
            .padding_budget_cap()
            .max(self.stealth.max_cover_budget_bytes());
        if padding_cap == 0 {
            self.padding_budget = 0;
            return 0;
        }

        let elapsed = self.last_padding_adjust.elapsed().as_secs();
        let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
        if ticks > 0 {
            let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
            self.padding_budget = self.padding_budget.saturating_add(growth).min(padding_cap);
            self.last_padding_adjust = Instant::now();
        }
        self.padding_budget.min(padding_cap)
    }

    fn on_remote_nack(&mut self, nack: &NackMessage) {
        let missing = nack.bitmap.count_ones() as usize;
        if missing == 0 {
            return;
        }

        if matches!(self.morphing_policy, MorphingPolicy::Off)
            && self.stealth.max_cover_budget_bytes() == 0
        {
            self.padding_budget = 0;
            self.redundancy_extra = 0;
            self.last_padding_adjust = Instant::now();
            self.last_redundancy_adjust = Instant::now();
            return;
        }

        let penalty = 16 + missing.saturating_mul(8);
        self.padding_budget = self
            .padding_budget
            .saturating_sub(penalty)
            .max(PADDING_BUDGET_MIN);
        self.last_padding_adjust = Instant::now();

        let bump = if missing >= 16 { 2 } else { 1 };
        self.redundancy_extra = self
            .redundancy_extra
            .saturating_add(bump)
            .min(REDUNDANCY_EXTRA_MAX);
        self.last_redundancy_adjust = Instant::now();
    }

    fn current_redundancy_extra(&mut self) -> usize {
        if matches!(self.morphing_policy, MorphingPolicy::Off) {
            self.redundancy_extra = 0;
            return 0;
        }

        let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
        let ticks = elapsed / REDUNDANCY_DECAY_SECS;
        if ticks > 0 {
            self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
            self.last_redundancy_adjust = Instant::now();
        }
        self.redundancy_extra as usize
    }

    fn update_loss_stats(&mut self, received_seq: u32) {
        if !self.loss_est_init {
            self.loss_est_seq = received_seq;
            self.loss_est_init = true;
            self.loss_estimator.record(true);
            return;
        }

        let diff = received_seq.wrapping_sub(self.loss_est_seq);
        if diff == 0 {
            return;
        }

        if diff < 0x8000_0000 {
            let lost_count = diff - 1;
            let to_record_lost = lost_count.min(256);

            for _ in 0..to_record_lost {
                self.loss_estimator.record(false);
            }
            self.loss_estimator.record(true);
            self.loss_est_seq = received_seq;
        }
    }

    fn loss_ratio(&self) -> f64 {
        self.loss_estimator.loss_ratio()
    }

    fn observe_inbound_seq(&mut self, seq: u32) -> Option<NackMessage> {
        let nack = self.gap_detector.record_received(seq);
        self.update_loss_stats(seq);
        nack
    }

    fn observe_transport_snapshot(&mut self, snapshot: &TransportSnapshot) {
        self.reliability.observe_path(&snapshot.path);
        self.fec_state.update(snapshot.path.loss_percent);
        let reliability = self.reliability.snapshot();
        self.stealth.observe_network(&snapshot.path, &reliability);
        self.live_fec.prune(Instant::now());
    }

    fn queue_protected_message(&mut self, class: TrafficClass, payload: Vec<u8>) -> u32 {
        let snapshot = self.transport.snapshot();
        self.observe_transport_snapshot(&snapshot);

        let message_id = self.transport.queue_message(class, payload.clone());
        if let Some(plan) = self.reliability.plan_for(class, payload.len()) {
            for _ in 0..plan.duplicate_packets {
                self.transport
                    .queue_duplicate_message(message_id, class, payload.clone());
                self.duplicate_packets_sent += 1;
            }

            if plan.repair_packets > 0 {
                if let Some(block) = self.fec_encoder.encode_live_block(
                    &payload,
                    plan.symbol_size,
                    plan.repair_packets,
                ) {
                    let frames =
                        build_live_fec_frames(message_id, class, &block.oti, &block.packets);
                    self.fec_frames_sent += frames.len() as u64;
                    for frame in frames {
                        self.transport.queue_fec_frame(frame);
                    }
                }
            }
        }

        message_id
    }

    fn accept_transport_messages(
        &mut self,
        now: Instant,
        messages: Vec<CompletedMessage>,
    ) -> Vec<CompletedMessage> {
        let mut accepted = Vec::with_capacity(messages.len());
        for message in messages {
            if self
                .live_fec
                .accept_transport_message(now, message.message_id)
            {
                accepted.push(message);
            } else {
                self.suppressed_duplicates += 1;
            }
        }
        accepted
    }

    fn recover_fec_messages(
        &mut self,
        now: Instant,
        frames: &[TransportFrame],
    ) -> Vec<CompletedMessage> {
        let mut recovered = Vec::new();
        for frame in frames {
            let TransportFrame::Fec(fec) = frame else {
                continue;
            };
            self.fec_frames_received += 1;
            if let Some(block) = self.live_fec.observe_frame(now, fec) {
                self.transport.discard_message(block.block_id);
                self.fec_recoveries += 1;
                recovered.push(CompletedMessage {
                    message_id: block.block_id,
                    class: block.class,
                    payload: block.payload,
                });
            }
        }
        recovered
    }

    fn stealth_padding_floor(
        &mut self,
        encoded_len: usize,
        payload_budget: usize,
        dynamic_padding_budget: usize,
    ) -> Option<usize> {
        self.stealth.target_padding_floor(
            encoded_len,
            payload_budget,
            dynamic_padding_budget,
            &mut self.chaos,
        )
    }

    fn stealth_snapshot(&self) -> StealthSnapshot {
        self.stealth.snapshot()
    }
    fn reliability_snapshot(&self) -> ReliabilitySnapshot {
        self.reliability.snapshot()
    }
}

#[allow(dead_code)]
fn current_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn get_ip_packet_len(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => {
            if buf.len() < 4 {
                return None;
            }
            Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
        6 => {
            if buf.len() < 6 {
                return None;
            }
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            Some(40 + payload_len)
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone)]
struct WindowsManagedRoute {
    destination: String,
    mask: String,
}

#[cfg(target_os = "windows")]
struct WindowsNetworkState {
    disabled_ipv6_adapters: Vec<String>,
    interface_alias: String,
    reset_dns: bool,
    managed_routes: Vec<WindowsManagedRoute>,
    route_conflict: Option<String>,
}

#[cfg(target_os = "windows")]
fn configure_windows_routing(
    server_ip: std::net::Ipv4Addr,
    tunnel_ip: std::net::Ipv4Addr,
    interface_mtu: u16,
    config: &ClientConfig,
) -> Option<WindowsNetworkState> {
    use std::process::Command;
    use std::time::Duration;

    tracing::info!(%tunnel_ip, "configuring Windows routing tables");

    let tunnel_ip_s = tunnel_ip.to_string();
    let mut if_index = String::new();
    let mut if_alias = String::new();

    for _ in 0..15 {
        let output_idx = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceIndex",
                    tunnel_ip_s
                ),
            ])
            .output();

        let output_alias = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceAlias",
                    tunnel_ip_s
                ),
            ])
            .output();

        if let (Ok(o_idx), Ok(o_alias)) = (output_idx, output_alias) {
            let idx_str = String::from_utf8_lossy(&o_idx.stdout).trim().to_string();
            let alias_str = String::from_utf8_lossy(&o_alias.stdout).trim().to_string();

            if !idx_str.is_empty() && !alias_str.is_empty() {
                if_index = idx_str;
                if_alias = alias_str;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if if_index.is_empty() || if_alias.is_empty() {
        tracing::error!("could not find Wintun interface");
        return None;
    }

    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &if_alias,
            &format!("mtu={}", interface_mtu),
            "store=active",
        ])
        .status();

    let set_metric_cmd = format!(
        "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -InterfaceMetric 1",
        powershell_quote(&if_alias)
    );
    let _ = Command::new("powershell")
        .args(["-Command", &set_metric_cmd])
        .status();

    let mut reset_dns = false;
    if config.should_set_tunnel_dns() && !config.dns_servers.is_empty() {
        let dns_ps = config
            .dns_servers
            .iter()
            .map(|v| format!("'{}'", v))
            .collect::<Vec<_>>()
            .join(",");
        let alias_ps = powershell_quote(&if_alias);
        let set_dns_cmd = format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
            alias_ps, dns_ps
        );
        let _ = Command::new("powershell")
            .args(["-Command", &set_dns_cmd])
            .status();
        reset_dns = true;
        tracing::info!(
            interface = %if_alias,
            dns = %config.dns_servers.join(","),
            "configured DNS on Wintun interface"
        );
    }

    let disabled_ipv6_adapters = if config.should_disable_ipv6() {
        configure_windows_ipv6_guard(&if_alias)
    } else {
        Vec::new()
    };

    let ps_cmd = format!(
        "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object {{ $_.InterfaceIndex -ne {} }} | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        if_index
    );

    let mut managed_routes = Vec::new();
    let server_route = WindowsManagedRoute {
        destination: server_ip.to_string(),
        mask: "255.255.255.255".to_string(),
    };
    delete_windows_route(&server_route);

    if let Ok(output) = Command::new("powershell")
        .args(["-Command", &ps_cmd])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(gateway) = stdout
            .lines()
            .next()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            add_windows_gateway_route(&server_route, gateway);
        }
    }

    match config.tunnel_mode {
        TunnelMode::Full => {
            let lower_half = WindowsManagedRoute {
                destination: "0.0.0.0".to_string(),
                mask: "128.0.0.0".to_string(),
            };
            let upper_half = WindowsManagedRoute {
                destination: "128.0.0.0".to_string(),
                mask: "128.0.0.0".to_string(),
            };
            delete_windows_route(&lower_half);
            delete_windows_route(&upper_half);
            add_windows_interface_route(&lower_half, &if_index);
            add_windows_interface_route(&upper_half, &if_index);
            managed_routes.push(lower_half);
            managed_routes.push(upper_half);
        }
        TunnelMode::Split => {
            for route in &config.split_routes {
                let managed = WindowsManagedRoute {
                    destination: route.destination.clone(),
                    mask: route.netmask.clone(),
                };
                delete_windows_route(&managed);
                add_windows_interface_route(&managed, &if_index);
                managed_routes.push(managed);
            }
        }
    }

    Some(WindowsNetworkState {
        disabled_ipv6_adapters,
        interface_alias: if_alias,
        reset_dns,
        managed_routes,
        route_conflict: if matches!(config.tunnel_mode, TunnelMode::Full) {
            verify_windows_full_tunnel_routes(&tunnel_ip_s).err()
        } else {
            None
        },
    })
}

#[cfg(target_os = "windows")]
fn cleanup_windows_routing(server_ip: std::net::Ipv4Addr, state: Option<&WindowsNetworkState>) {
    use std::process::Command;

    if let Some(state) = state {
        if state.reset_dns {
            let reset_dns = format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
                powershell_quote(&state.interface_alias)
            );
            let _ = Command::new("powershell")
                .args(["-Command", &reset_dns])
                .status();
        }

        let reset_metric = format!(
            "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -AutomaticMetric Enabled",
            powershell_quote(&state.interface_alias)
        );
        let _ = Command::new("powershell")
            .args(["-Command", &reset_metric])
            .status();

        restore_windows_ipv6_guard(&state.disabled_ipv6_adapters);

        for route in &state.managed_routes {
            delete_windows_route(route);
        }
    }

    delete_windows_route(&WindowsManagedRoute {
        destination: server_ip.to_string(),
        mask: "255.255.255.255".to_string(),
    });
}

#[cfg(not(target_os = "windows"))]
fn configure_windows_routing(
    _: std::net::Ipv4Addr,
    _: std::net::Ipv4Addr,
    _: u16,
    _: &ClientConfig,
) -> Option<()> {
    None
}
#[cfg(not(target_os = "windows"))]
fn cleanup_windows_routing(_: std::net::Ipv4Addr, _: Option<&()>) {}

#[cfg(target_os = "windows")]
fn add_windows_gateway_route(route: &WindowsManagedRoute, gateway: &str) {
    let _ = std::process::Command::new("route")
        .args([
            "add",
            &route.destination,
            "mask",
            &route.mask,
            gateway,
            "metric",
            "1",
        ])
        .status();
}

#[cfg(target_os = "windows")]
fn add_windows_interface_route(route: &WindowsManagedRoute, if_index: &str) {
    let _ = std::process::Command::new("route")
        .args([
            "add",
            &route.destination,
            "mask",
            &route.mask,
            "0.0.0.0",
            "IF",
            if_index,
            "metric",
            "1",
        ])
        .status();
}

#[cfg(target_os = "windows")]
fn delete_windows_route(route: &WindowsManagedRoute) {
    let _ = std::process::Command::new("route")
        .args(["delete", &route.destination, "mask", &route.mask])
        .status();
}

#[cfg(target_os = "windows")]
fn verify_windows_full_tunnel_routes(tunnel_ip: &str) -> Result<(), String> {
    let output = std::process::Command::new("route")
        .args(["print", "-4"])
        .output()
        .map_err(|err| format!("failed to inspect Windows routes: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary = summarize_windows_full_tunnel_routes(&stdout, tunnel_ip);

    if summary.lower_half_ok && summary.upper_half_ok {
        return Ok(());
    }

    let mut details = Vec::new();
    if !summary.conflicting_routes.is_empty() {
        details.push(format!(
            "observed competing routes: {}",
            summary.conflicting_routes.join(" | ")
        ));
    }

    let conflicting_processes = detect_conflicting_tunnel_processes();
    if !conflicting_processes.is_empty() {
        details.push(format!(
            "running tunnel processes: {}",
            conflicting_processes.join(", ")
        ));
    }

    let suffix = if details.is_empty() {
        String::new()
    } else {
        format!(" ({})", details.join("; "))
    };

    Err(format!(
        "Windows full-tunnel routes are not owned by Omega interface {}{}",
        tunnel_ip, suffix
    ))
}

#[cfg(target_os = "windows")]
struct WindowsFullTunnelRouteSummary {
    lower_half_ok: bool,
    upper_half_ok: bool,
    conflicting_routes: Vec<String>,
}

#[cfg(target_os = "windows")]
fn summarize_windows_full_tunnel_routes(
    route_print: &str,
    tunnel_ip: &str,
) -> WindowsFullTunnelRouteSummary {
    let mut lower_half_ok = false;
    let mut upper_half_ok = false;
    let mut conflicting_routes = Vec::new();

    for line in route_print.lines() {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 5 {
            continue;
        }

        let is_lower_half = cols[0] == "0.0.0.0" && cols[1] == "128.0.0.0";
        let is_upper_half = cols[0] == "128.0.0.0" && cols[1] == "128.0.0.0";
        if !is_lower_half && !is_upper_half {
            continue;
        }

        let interface = cols[3];
        if interface == tunnel_ip {
            if is_lower_half {
                lower_half_ok = true;
            } else {
                upper_half_ok = true;
            }
        } else {
            conflicting_routes.push(line.trim().to_string());
        }
    }

    WindowsFullTunnelRouteSummary {
        lower_half_ok,
        upper_half_ok,
        conflicting_routes,
    }
}

#[cfg(target_os = "windows")]
fn detect_conflicting_tunnel_processes() -> Vec<String> {
    let Ok(output) = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    else {
        return Vec::new();
    };

    let needles = [
        "tun2socks.exe",
        "xray.exe",
        "v2ray.exe",
        "sing-box.exe",
        "clash.exe",
        "clash-verge.exe",
        "mihomo.exe",
        "nekoray.exe",
        "hysteria.exe",
        "amneziavpn.exe",
    ];

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let name = line
                .trim()
                .trim_matches('"')
                .split("\",\"")
                .next()
                .map(str::to_ascii_lowercase)?;
            if needles.iter().any(|needle| name == *needle) {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn powershell_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn configure_windows_ipv6_guard(wintun_alias: &str) -> Vec<String> {
    use std::process::Command;

    let list_cmd = format!(
        "Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true -and $_.Name -ne '{}' -and $_.InterfaceDescription -notlike '*Wintun*' }} | ForEach-Object {{ $binding = Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; if ($binding -and $binding.Enabled) {{ $_.Name }} }}",
        powershell_quote(wintun_alias)
    );

    let Ok(output) = Command::new("powershell")
        .args(["-Command", &list_cmd])
        .output()
    else {
        return Vec::new();
    };

    let adapters = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    for adapter in &adapters {
        let disable_cmd = format!(
            "Disable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -Confirm:$false | Out-Null",
            powershell_quote(adapter)
        );
        let _ = Command::new("powershell")
            .args(["-Command", &disable_cmd])
            .status();
    }

    if !adapters.is_empty() {
        tracing::info!(
            adapters = %adapters.join(","),
            "disabled IPv6 on active physical adapters while VPN is running"
        );
    }

    adapters
}

#[cfg(target_os = "windows")]
fn restore_windows_ipv6_guard(adapters: &[String]) {
    use std::process::Command;

    for adapter in adapters {
        let enable_cmd = format!(
            "Enable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -Confirm:$false | Out-Null",
            powershell_quote(adapter)
        );
        let _ = Command::new("powershell")
            .args(["-Command", &enable_cmd])
            .status();
    }

    if !adapters.is_empty() {
        tracing::info!(
            adapters = %adapters.join(","),
            "restored IPv6 on physical adapters"
        );
    }
}

fn detect_platform() -> DevicePlatform {
    #[cfg(target_os = "windows")]
    {
        return DevicePlatform::Windows;
    }
    #[cfg(target_os = "linux")]
    {
        return DevicePlatform::Linux;
    }
    #[cfg(target_os = "macos")]
    {
        return DevicePlatform::Macos;
    }
    #[cfg(target_os = "android")]
    {
        return DevicePlatform::Android;
    }
    #[cfg(target_os = "ios")]
    {
        return DevicePlatform::Ios;
    }
    #[allow(unreachable_code)]
    DevicePlatform::Other
}

fn parse_uuid(value: &str) -> anyhow::Result<[u8; 16]> {
    let compact = value.replace('-', "");
    if compact.len() != 32 {
        return Err(anyhow::anyhow!("device_id must be UUID"));
    }

    let mut out = [0u8; 16];
    let bytes = compact.as_bytes();
    for i in 0..16 {
        let hi = hex_value(bytes[i * 2])
            .ok_or_else(|| anyhow::anyhow!("invalid device_id hex at pos {}", i * 2))?;
        let lo = hex_value(bytes[i * 2 + 1])
            .ok_or_else(|| anyhow::anyhow!("invalid device_id hex at pos {}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_token(value: &str) -> anyhow::Result<[u8; DEVICE_TOKEN_LEN]> {
    if value.len() != DEVICE_TOKEN_LEN * 2 {
        return Err(anyhow::anyhow!(
            "device token must be {} hex chars",
            DEVICE_TOKEN_LEN * 2
        ));
    }

    let mut out = [0u8; DEVICE_TOKEN_LEN];
    let bytes = value.as_bytes();
    for i in 0..DEVICE_TOKEN_LEN {
        let hi = hex_value(bytes[i * 2])
            .ok_or_else(|| anyhow::anyhow!("invalid token hex at pos {}", i * 2))?;
        let lo = hex_value(bytes[i * 2 + 1])
            .ok_or_else(|| anyhow::anyhow!("invalid token hex at pos {}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
    }
}

fn build_dns_query(hostname: &str, txid: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in hostname.split('.').filter(|part| !part.is_empty()) {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

async fn run_udp_dns_diagnostic(
    dns_servers: Vec<String>,
    enabled: bool,
    diagnostics: ClientDiagnostics,
) {
    if !enabled {
        diagnostics.udp_check_failed("disabled by OMEGA_NETWORK_DIAG=0");
        return;
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    let targets = dns_servers
        .into_iter()
        .filter_map(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .collect::<Vec<_>>();
    if targets.is_empty() {
        tracing::warn!("UDP diagnostic skipped: no valid DNS servers");
        diagnostics.udp_check_failed("no valid DNS servers configured");
        return;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::warn!(error = %err, "UDP diagnostic failed to bind socket");
            diagnostics.udp_check_failed(format!("failed to bind socket: {err}"));
            return;
        }
    };

    let txid: u16 = rand::random();
    let query = build_dns_query("example.com", txid);
    let mut buf = [0u8; 1500];

    for dns_ip in targets {
        let target = SocketAddr::from((dns_ip, 53));
        if let Err(err) = socket.send_to(&query, target).await {
            tracing::warn!(error = %err, %target, "UDP diagnostic send failed");
            continue;
        }

        match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if n >= 4 && u16::from_be_bytes([buf[0], buf[1]]) == txid && (buf[2] & 0x80) != 0 {
                    tracing::info!(
                        %src,
                        dns_server = %target,
                        "UDP DNS diagnostic passed; generic UDP through the tunnel works"
                    );
                    diagnostics.udp_check_passed(target, src);
                    return;
                }
                tracing::warn!(
                    %src,
                    dns_server = %target,
                    bytes = n,
                    "UDP diagnostic got an unexpected reply"
                );
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, %target, "UDP diagnostic receive failed");
            }
            Err(_) => {
                tracing::warn!(
                    %target,
                    "UDP diagnostic timed out; generic UDP through the tunnel may be blocked"
                );
            }
        }
    }

    tracing::warn!(
        "all UDP DNS diagnostics failed; if websites still open, the remaining problem is likely blocked outbound UDP on the VPS/provider side"
    );
    diagnostics.udp_check_failed(
        "all UDP DNS checks timed out or returned unexpected replies".to_string(),
    );
}

async fn run_client_transport_tx(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    server_addr: SocketAddr,
    flow_id: FlowId,
    state: Arc<Mutex<ClientState>>,
    diagnostics: ClientDiagnostics,
    keepalive_secs: u64,
) {
    let mut buf = vec![0u8; 1500];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = keepalive_interval.tick() => {
                {
                    let mut state = state.lock().unwrap();
                    state.transport.queue_keepalive();
                }
                drain_client_outbound(&state, &udp, server_addr, flow_id, &diagnostics).await;
            }
            res = tun.recv(&mut buf) => {
                let n = match res {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!(error = %e, "TUN read failed");
                        continue;
                    }
                };
                diagnostics.note_tun_packet();
                {
                    let mut state = state.lock().unwrap();
                    state.queue_protected_message(classify_ip_packet(&buf[..n]), buf[..n].to_vec());
                }
                drain_client_outbound(&state, &udp, server_addr, flow_id, &diagnostics).await;
            }
        }
    }
}

async fn run_client_transport_rx(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    server_addr: SocketAddr,
    flow_id: FlowId,
    state: Arc<Mutex<ClientState>>,
    diagnostics: ClientDiagnostics,
) {
    let mut replay_filter = ReplayFilter::new();
    let mut buf = vec![0u8; 2048];

    loop {
        let (n, _src) = match udp.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "UDP recv failed");
                continue;
            }
        };
        diagnostics.note_server_packet();
        if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
            continue;
        }

        let Some(rtp) = RtpHeader::read_from(&buf[..RTP_HEADER_LEN]) else {
            continue;
        };
        let Some(raw_flow_id) = FlowId::from_bytes(&buf[RTP_HEADER_LEN..RTP_HEADER_LEN + 16])
        else {
            continue;
        };
        if raw_flow_id != flow_id {
            continue;
        }

        let (
            messages,
            snapshot,
            padding_budget,
            redundancy_extra,
            reliability,
            stealth,
            counters,
            should_close,
        ) = {
            let mut state = state.lock().unwrap();
            let Some(omega) = read_protected_omega_header(
                &rtp,
                &state.header_protection,
                &buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN],
            ) else {
                continue;
            };
            if !matches!(omega.packet_type, PacketType::Data | PacketType::Close) {
                continue;
            }
            if !replay_filter.check(omega.seq as u64) {
                continue;
            }
            let Some(keys) = state.keys.as_mut() else {
                continue;
            };
            let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);
            let plaintext = match keys.decrypt_in_place(ciphertext, omega.seq as u64, aad) {
                Ok(plaintext) => plaintext.to_vec(),
                Err(e) => {
                    tracing::warn!(error = %e, seq = omega.seq, "auth failed");
                    continue;
                }
            };
            replay_filter.update(omega.seq as u64);
            let Some(frames) = decode_transport_frames(&plaintext) else {
                continue;
            };
            let should_close = omega.packet_type == PacketType::Close
                || frames.iter().any(|frame| matches!(frame, TransportFrame::Control(control) if matches!(control.kind, ControlKind::Close)));
            let now = Instant::now();
            let messages = state
                .transport
                .on_datagram_received(now, omega.seq, &frames);
            let mut messages = state.accept_transport_messages(now, messages);
            let recovered = state.recover_fec_messages(now, &frames);
            messages.extend(recovered);
            let snapshot = state.transport.snapshot();
            state.observe_transport_snapshot(&snapshot);
            let padding_budget = state.current_padding_budget();
            let redundancy_extra = state.current_redundancy_extra();
            let reliability = state.reliability_snapshot();
            let stealth = state.stealth_snapshot();
            let counters = (
                state.fec_frames_sent,
                state.fec_frames_received,
                state.fec_recoveries,
                state.duplicate_packets_sent,
                state.suppressed_duplicates,
            );
            (
                messages,
                snapshot,
                padding_budget,
                redundancy_extra,
                reliability,
                stealth,
                counters,
                should_close,
            )
        };

        diagnostics.update_path_metrics(&snapshot, padding_budget, redundancy_extra);
        diagnostics.update_reliability_metrics(
            &reliability,
            counters.0,
            counters.1,
            counters.2,
            counters.3,
            counters.4,
        );
        diagnostics.update_stealth_metrics(&stealth);

        for message in messages {
            let final_len = if let Some(ip_len) = get_ip_packet_len(&message.payload) {
                message.payload.len().min(ip_len)
            } else {
                message.payload.len()
            };
            if let Err(e) = tun.send(&message.payload[..final_len]).await {
                tracing::error!(error = %e, "TUN write failed");
            }
        }

        if should_close {
            diagnostics.set_status("server_closed");
            tracing::warn!("session closed by server");
            return;
        }
        drain_client_outbound(&state, &udp, server_addr, flow_id, &diagnostics).await;
    }
}

async fn drain_client_outbound(
    state: &Arc<Mutex<ClientState>>,
    udp: &Arc<UdpSocket>,
    server_addr: SocketAddr,
    flow_id: FlowId,
    diagnostics: &ClientDiagnostics,
) {
    for _ in 0..MAX_RETRANSMIT_BURST {
        let prepared = {
            let mut state = state.lock().unwrap();
            if !state.transport.has_pending_work() {
                return;
            }
            if let Some(deadline) = state.transport.next_send_deadline() {
                if deadline > Instant::now() {
                    return;
                }
            }
            let payload_budget = state.transport_payload_budget;
            let padding_budget = state.current_padding_budget();
            let mut datagram = match state
                .transport
                .poll_datagram(Instant::now(), payload_budget)
            {
                Some(datagram) => datagram,
                None => return,
            };
            if let Some(target_floor) =
                state.stealth_padding_floor(datagram.encoded_len, payload_budget, padding_budget)
            {
                if target_floor > datagram.encoded_len + 3 {
                    datagram.frames.push(TransportFrame::Padding(
                        target_floor - datagram.encoded_len - 3,
                    ));
                    datagram.encoded_len = encode_transport_frames(&datagram.frames).len();
                }
            }
            let packet_number = datagram.packet_number;
            let packet = match build_client_wire_packet(flow_id, &mut state, datagram) {
                Some(packet) => packet,
                None => {
                    state.transport.abort_sent(packet_number);
                    return;
                }
            };
            let snapshot = state.transport.snapshot();
            state.observe_transport_snapshot(&snapshot);
            let padding_budget = state.current_padding_budget();
            let redundancy_extra = state.current_redundancy_extra();
            let reliability = state.reliability_snapshot();
            let stealth = state.stealth_snapshot();
            let counters = (
                state.fec_frames_sent,
                state.fec_frames_received,
                state.fec_recoveries,
                state.duplicate_packets_sent,
                state.suppressed_duplicates,
            );
            (
                packet_number,
                packet,
                snapshot,
                padding_budget,
                redundancy_extra,
                reliability,
                stealth,
                counters,
            )
        };

        let (
            packet_number,
            packet,
            snapshot,
            padding_budget,
            redundancy_extra,
            reliability,
            stealth,
            counters,
        ) = prepared;
        if let Err(e) = udp.send_to(packet.as_ref(), server_addr).await {
            tracing::error!(error = %e, "UDP send failed");
            let mut state = state.lock().unwrap();
            state.transport.abort_sent(packet_number);
            return;
        }
        diagnostics.update_path_metrics(&snapshot, padding_budget, redundancy_extra);
        diagnostics.update_reliability_metrics(
            &reliability,
            counters.0,
            counters.1,
            counters.2,
            counters.3,
            counters.4,
        );
        diagnostics.update_stealth_metrics(&stealth);
    }
}

fn build_client_wire_packet(
    flow_id: FlowId,
    state: &mut ClientState,
    datagram: omega_transport::transport_v2::OutboundDatagram,
) -> Option<Bytes> {
    let payload_bytes = encode_transport_frames(&datagram.frames);
    let is_small = payload_bytes.len() < 500;
    state.rtp_seq = state.rtp_seq.wrapping_add(1);
    state.rtp_timestamp = state
        .rtp_timestamp
        .wrapping_add(if is_small { 960 } else { 3000 });
    let rtp = if is_small {
        RtpHeader::opus(state.rtp_seq, state.rtp_timestamp, state.ssrc)
    } else {
        RtpHeader::vp8(state.rtp_seq, state.rtp_timestamp, state.ssrc, true)
    };
    let omega = OmegaHeader {
        flow_id,
        seq: datagram.packet_number,
        packet_type: control_packet_type(&datagram.frames),
    };

    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + payload_bytes.len() + AEAD_TAG_LEN);
    out.resize(TOTAL_HEADER_LEN, 0);
    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
    write_protected_omega_header(
        &omega,
        &rtp,
        &state.header_protection,
        &mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN],
    );

    let aad = &out[..TOTAL_HEADER_LEN];
    let mut payload = payload_bytes;
    let nonce = state
        .keys
        .as_mut()?
        .encrypt_in_place(&mut payload, aad)
        .ok()?;
    if nonce != datagram.packet_number as u64 {
        tracing::warn!(
            expected = datagram.packet_number,
            actual = nonce,
            "client transport packet number drifted from AEAD nonce"
        );
        return None;
    }
    out.extend_from_slice(&payload);
    Some(out.freeze())
}

fn classify_ip_packet(buf: &[u8]) -> TrafficClass {
    if buf.len() < 20 {
        return TrafficClass::Interactive;
    }
    match buf[0] >> 4 {
        4 => match buf[9] {
            1 | 17 => TrafficClass::Interactive,
            _ if buf.len() <= 700 => TrafficClass::Interactive,
            _ => TrafficClass::Bulk,
        },
        6 => match buf.get(6).copied().unwrap_or_default() {
            58 | 17 => TrafficClass::Interactive,
            _ if buf.len() <= 700 => TrafficClass::Interactive,
            _ => TrafficClass::Bulk,
        },
        _ if buf.len() <= 700 => TrafficClass::Interactive,
        _ => TrafficClass::Bulk,
    }
}
pub async fn run_from_env() -> anyhow::Result<()> {
    tracing::info!("omega-client v{} starting", env!("CARGO_PKG_VERSION"));

    let client_config = ClientConfig::from_env();
    let server_endpoint =
        std::env::var("OMEGA_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let device_name =
        std::env::var("OMEGA_DEVICE_NAME").unwrap_or_else(|_| "omega-client".to_string());
    let background_mode = env_bool("OMEGA_BACKGROUND_MODE", false);
    let lifecycle = ClientLifecycle::new(
        client_config.lifecycle_path.clone(),
        client_config.profile,
        server_endpoint.clone(),
        device_name.clone(),
        background_mode,
    );
    lifecycle.set_state(
        ClientLifecycleState::Starting,
        "validating desktop runtime configuration",
    );
    let _ = std::fs::remove_file(&client_config.control_path);

    let mut failure_scope = ClientFailureScope::Config;
    let result: anyhow::Result<()> = async {
        let server_addr: SocketAddr = server_endpoint
            .parse()
            .with_context(|| format!("failed to parse OMEGA_SERVER={server_endpoint}"))?;

        failure_scope = ClientFailureScope::Credentials;
        let device_id = parse_uuid(
            &std::env::var("OMEGA_DEVICE_ID")
                .context("OMEGA_DEVICE_ID is required (UUID from admin register_device)")?,
        )?;
        let device_token = parse_token(
            &std::env::var("OMEGA_DEVICE_TOKEN")
                .context("OMEGA_DEVICE_TOKEN is required (token from admin register_device)")?,
        )?;
        let platform = std::env::var("OMEGA_PLATFORM")
            .ok()
            .and_then(|value| {
                DevicePlatform::from_u8(match value.to_ascii_lowercase().as_str() {
                    "windows" => 1,
                    "linux" => 2,
                    "macos" => 3,
                    "android" => 4,
                    "ios" => 5,
                    _ => 255,
                })
            })
            .unwrap_or_else(detect_platform);
        let platform_label = match platform {
            DevicePlatform::Windows => "windows",
            DevicePlatform::Linux => "linux",
            DevicePlatform::Macos => "macos",
            DevicePlatform::Android => "android",
            DevicePlatform::Ios => "ios",
            DevicePlatform::Other => "other",
        };

        let diagnostics = ClientDiagnostics::new(
            client_config.diagnostics_path.clone(),
            &client_config,
            server_addr,
            &device_name,
            platform_label,
        );
        diagnostics.spawn_writer();
        diagnostics.set_status("starting");

        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        let _ = socket.set_recv_buffer_size(client_config.udp_rcvbuf);
        let _ = socket.set_send_buffer_size(client_config.udp_sndbuf);

        let addr: SocketAddr = "0.0.0.0:0".parse()?;
        socket.bind(&addr.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        let udp = Arc::new(UdpSocket::from_std(std_socket)?);
        tracing::info!(local_addr = %udp.local_addr()?, "UDP socket bound");

        let credentials = ClientCredentialPayload {
            device_id,
            device_token,
            platform,
            device_name: device_name.clone(),
        };

        let keepalive_secs = client_config.keepalive_secs;
        lifecycle.set_state(
            ClientLifecycleState::Handshaking,
            "performing authenticated handshake with the selected profile",
        );
        diagnostics.set_status("handshaking");
        failure_scope = ClientFailureScope::Handshake;
        let handshake = perform_handshake_v2(&udp, server_addr, &credentials, &client_config).await?;
        let server_hello = handshake.complete.clone();
        let flow_id = server_hello.flow_id;
        let flow_id_bytes = *flow_id.as_bytes();
        let chaos_seed = u64::from_le_bytes(
            handshake.secrets.app_secret[0..8]
                .try_into()
                .unwrap_or_default(),
        );
        let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap_or_default());
        let session_keys_template = handshake.secrets.session_keys.clone();

        let tun_ip = server_hello.tunnel_ip;
        let tun_ip_s = tun_ip.to_string();
        let tun: Arc<tun_rs::AsyncDevice> = Arc::new(
            tun_rs::DeviceBuilder::new()
                .ipv4(tun_ip_s.clone(), DEFAULT_TUN_PREFIX, None)
                .mtu(server_hello.server_mtu)
                .with(|builder| {
                    #[cfg(target_os = "windows")]
                    {
                        let ring_capacity =
                            client_config.udp_rcvbuf.clamp(0x2_0000, 0x400_0000) as u32;
                        builder.ring_capacity(ring_capacity);
                    }
                })
                .build_async()?,
        );
        if let Ok(interface_name) = tun.name() {
            diagnostics.set_interface_name(interface_name.clone());
            tracing::info!(%interface_name, %tun_ip, server_mtu = server_hello.server_mtu, "handshake complete");
        } else {
            tracing::info!(%tun_ip, server_mtu = server_hello.server_mtu, "handshake complete");
        }
        diagnostics.set_handshake(tun_ip, server_hello.server_mtu, handshake.rtt_ms);
        lifecycle.mark_connected(tun_ip, handshake.rtt_ms);

        failure_scope = ClientFailureScope::Routing;
        #[cfg(target_os = "windows")]
        let windows_state = if let std::net::SocketAddr::V4(v4) = server_addr {
            let state = configure_windows_routing(
                *v4.ip(),
                tun_ip,
                server_hello.server_mtu,
                &client_config,
            );
            if matches!(client_config.tunnel_mode, TunnelMode::Full) {
                match state.as_ref() {
                    Some(state) if state.route_conflict.is_none() => {}
                    Some(state) => {
                        let err = state.route_conflict.clone().unwrap_or_else(|| {
                            "Windows full-tunnel routing verification failed".to_string()
                        });
                        diagnostics.set_status("routing_failed");
                        cleanup_windows_routing(*v4.ip(), Some(state));
                        return Err(anyhow::anyhow!(err));
                    }
                    None => {
                        diagnostics.set_status("routing_failed");
                        return Err(anyhow::anyhow!(
                            "failed to configure Windows full-tunnel routes; stop other VPN/tun2socks adapters and retry"
                        ));
                    }
                }
            }
            state
        } else {
            None
        };

        let diag_dns_servers = client_config.dns_servers.clone();
        let diag_enabled = client_config.network_diag;
        let diag_handle = diagnostics.clone();
        tokio::spawn(async move {
            run_udp_dns_diagnostic(diag_dns_servers, diag_enabled, diag_handle).await;
        });

        let state = Arc::new(Mutex::new(ClientState::new(
            ssrc,
            chaos_seed,
            client_config.morphing_policy,
            client_config.persona,
        )));
        {
            let mut state_guard = state.lock().unwrap();
            state_guard.configure_transport(
                server_hello.connection_id,
                handshake.secrets.update_secret,
                handshake.secrets.app_secret,
                server_hello.server_mtu,
            );
            state_guard.install_session_keys(session_keys_template.clone());
            let padding_budget = state_guard.current_padding_budget();
            let redundancy_extra = state_guard.current_redundancy_extra();
            let snapshot = state_guard.transport.snapshot();
            state_guard.observe_transport_snapshot(&snapshot);
            let reliability = state_guard.reliability_snapshot();
            let stealth = state_guard.stealth_snapshot();
            let counters = (
                state_guard.fec_frames_sent,
                state_guard.fec_frames_received,
                state_guard.fec_recoveries,
                state_guard.duplicate_packets_sent,
                state_guard.suppressed_duplicates,
            );
            diagnostics.update_stealth_metrics(&stealth);
            diagnostics.update_path_metrics(&snapshot, padding_budget, redundancy_extra);
            diagnostics.update_reliability_metrics(
                &reliability,
                counters.0,
                counters.1,
                counters.2,
                counters.3,
                counters.4,
            );
        }

        let tun_r = tun.clone();
        let udp_r = udp.clone();
        let flow_id_copy = flow_id;
        let state_send = state.clone();
        let diagnostics_send = diagnostics.clone();

        tokio::spawn(async move {
            run_client_transport_tx(
                tun_r,
                udp_r,
                server_addr,
                flow_id_copy,
                state_send,
                diagnostics_send,
                keepalive_secs,
            )
            .await;
        });

        let tun_w = tun.clone();
        let udp_w = udp.clone();
        let state_recv = state.clone();
        let diagnostics_recv = diagnostics.clone();

        tokio::spawn(async move {
            run_client_transport_rx(
                tun_w,
                udp_w,
                server_addr,
                flow_id,
                state_recv,
                diagnostics_recv,
            )
            .await;
        });
        tracing::info!("data path running in background mode");

        failure_scope = ClientFailureScope::Shutdown;
        let stop_reason = tokio::select! {
            _ = tokio::signal::ctrl_c() => "local console requested stop".to_string(),
            command = wait_for_runtime_stop(client_config.control_path.clone()) => {
                command.reason.unwrap_or_else(|| "desktop app requested stop".to_string())
            }
        };
        diagnostics.set_status("stopping");
        lifecycle.set_state(
            ClientLifecycleState::Closing,
            format!("stopping runtime: {stop_reason}"),
        );
        tracing::info!(reason = %stop_reason, "shutting down");

        #[cfg(target_os = "windows")]
        {
            if let std::net::SocketAddr::V4(v4) = server_addr {
                cleanup_windows_routing(*v4.ip(), windows_state.as_ref());
            }
        }

        diagnostics.set_status("stopped");
        lifecycle.mark_stopped("desktop runtime stopped cleanly");
        Ok(())
    }
    .await;

    if let Err(err) = result {
        lifecycle.record_failure(failure_scope, err.to_string());
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_control_seq_does_not_create_false_gap() {
        let mut state =
            ClientState::new(0xDEADBEEF, 7, MorphingPolicy::Balanced, PersonaId::QuicLike);

        assert!(state.observe_inbound_seq(100).is_none());
        assert!(state.observe_inbound_seq(101).is_none()); // keepalive/nack seq
        assert!(state.observe_inbound_seq(102).is_none());
        assert_eq!(state.loss_ratio(), 0.0);
    }

    #[test]
    fn missing_seq_is_still_reported_after_control_packet() {
        let mut state =
            ClientState::new(0xDEADBEEF, 7, MorphingPolicy::Balanced, PersonaId::QuicLike);

        assert!(state.observe_inbound_seq(10).is_none());
        assert!(state.observe_inbound_seq(11).is_none()); // observed control seq
        assert!(state.observe_inbound_seq(13).is_none());
        let mut emitted_nack = false;
        for seq in 14..30 {
            if state.observe_inbound_seq(seq).is_some() {
                emitted_nack = true;
                break;
            }
        }
        assert!(emitted_nack, "gap should eventually trigger a nack");
        assert!(state.loss_ratio() > 0.0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn full_tunnel_route_summary_accepts_omega_owned_routes() {
        let summary = summarize_windows_full_tunnel_routes(
            "\
Network Destination        Netmask          Gateway       Interface  Metric\n\
          0.0.0.0        128.0.0.0         On-link         10.7.0.2      6\n\
        128.0.0.0        128.0.0.0         On-link         10.7.0.2      6\n",
            "10.7.0.2",
        );

        assert!(summary.lower_half_ok);
        assert!(summary.upper_half_ok);
        assert!(summary.conflicting_routes.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn full_tunnel_route_summary_detects_competing_tunnel() {
        let summary = summarize_windows_full_tunnel_routes(
            "\
Network Destination        Netmask          Gateway       Interface  Metric\n\
          0.0.0.0        128.0.0.0         On-link        10.33.0.2      6\n\
        128.0.0.0        128.0.0.0         On-link        10.33.0.2      6\n",
            "10.7.0.2",
        );

        assert!(!summary.lower_half_ok);
        assert!(!summary.upper_half_ok);
        assert_eq!(summary.conflicting_routes.len(), 2);
    }
}
