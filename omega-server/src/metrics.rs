use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

pub fn init_metrics(port: u16) -> anyhow::Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()?;

    gauge!("omega_active_sessions").set(0.0);
    tracing::info!(port, "prometheus metrics enabled");
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
