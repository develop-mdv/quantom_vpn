use std::net::SocketAddr;

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::runtime::RuntimeSummary;

pub fn init_metrics(bind: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = bind.parse()?;
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    gauge!("omega_active_sessions").set(0.0);
    gauge!("omega_runtime_max_idle_seconds").set(0.0);
    gauge!("omega_runtime_max_age_seconds").set(0.0);
    gauge!("omega_runtime_avg_loss_ratio").set(0.0);
    tracing::info!(%addr, "prometheus metrics enabled");
    Ok(())
}

pub fn record_packet_out(bytes: usize) {
    counter!("omega_packets_out_total").increment(1);
    counter!("omega_bytes_out_total").increment(bytes as u64);
}

pub fn record_packet_in(bytes: usize) {
    counter!("omega_packets_in_total").increment(1);
    counter!("omega_bytes_in_total").increment(bytes as u64);
}

pub fn update_session_count(count: usize) {
    gauge!("omega_active_sessions").set(count as f64);
}

pub fn update_user_session_count(user_id: &str, count: usize) {
    gauge!("omega_active_sessions_per_user", "user_id" => user_id.to_string()).set(count as f64);
}

pub fn record_handshake_success(user_id: String, platform: &str) {
    counter!("omega_handshake_success_total").increment(1);
    counter!("omega_handshake_platform_total", "platform" => platform.to_string()).increment(1);
    counter!("omega_handshake_success_per_user_total", "user_id" => user_id).increment(1);
}

pub fn record_device_reconnect(replaced_sessions: usize) {
    counter!("omega_device_reconnect_total").increment(1);
    counter!("omega_device_reconnect_replaced_sessions_total").increment(replaced_sessions as u64);
}

pub fn record_handshake_failure(reason: omega_core::protocol::HandshakeRejectReason) {
    let reason_label = format!("{:?}", reason).to_ascii_lowercase();
    counter!("omega_handshake_failures_total", "reason" => reason_label).increment(1);
}

pub fn record_ip_lease_assigned() {
    counter!("omega_ip_leases_assigned_total").increment(1);
}

pub fn record_ip_lease_released() {
    counter!("omega_ip_leases_released_total").increment(1);
}

pub fn record_nack_sent(missing_packets: u32) {
    counter!("omega_nack_sent_total").increment(1);
    counter!("omega_nack_sent_missing_packets_total").increment(missing_packets as u64);
}

pub fn record_nack_received(missing_packets: u32) {
    counter!("omega_nack_received_total").increment(1);
    counter!("omega_nack_received_missing_packets_total").increment(missing_packets as u64);
}

pub fn record_retransmit_sent(sent_packets: usize, dropped_packets: usize) {
    counter!("omega_retransmit_sent_total").increment(sent_packets as u64);
    if dropped_packets > 0 {
        counter!("omega_retransmit_dropped_total").increment(dropped_packets as u64);
    }
}

pub fn update_runtime_summary(summary: &RuntimeSummary) {
    gauge!("omega_runtime_max_idle_seconds").set(summary.max_idle_secs as f64);
    gauge!("omega_runtime_max_age_seconds").set(summary.max_age_secs as f64);
    gauge!("omega_runtime_avg_loss_ratio").set(summary.avg_loss_ratio);
}

// -----------------------------------------------------------------------------
// REALITY transport metrics
// -----------------------------------------------------------------------------

pub fn record_reality_handshake_authentic(short_id_hex: String) {
    counter!("omega_reality_handshakes_total", "verdict" => "authentic").increment(1);
    counter!("omega_reality_handshakes_by_short_id_total", "short_id" => short_id_hex)
        .increment(1);
}

pub fn record_reality_handshake_foreign() {
    counter!("omega_reality_handshakes_total", "verdict" => "foreign").increment(1);
}

pub fn record_reality_handshake_error(reason: &str) {
    counter!("omega_reality_handshake_errors_total", "reason" => reason.to_string()).increment(1);
}

pub fn record_reality_proxy_bytes(direction: &'static str, bytes: u64) {
    if bytes > 0 {
        counter!("omega_reality_proxy_bytes_total", "direction" => direction).increment(bytes);
    }
}

pub fn reality_active_tunnels_inc() {
    gauge!("omega_reality_active_tunnels").increment(1.0);
}

pub fn reality_active_tunnels_dec() {
    gauge!("omega_reality_active_tunnels").decrement(1.0);
}

pub fn record_reality_cert_refresh(sni: &str, rotated: bool) {
    counter!(
        "omega_reality_cert_refresh_total",
        "sni" => sni.to_string(),
        "rotated" => if rotated { "true".to_string() } else { "false".to_string() }
    )
    .increment(1);
}
