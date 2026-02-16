/// Metrics — Prometheus endpoint for monitoring.

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Initialize the Prometheus metrics exporter on the given port.
pub fn init_metrics(port: u16) -> anyhow::Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()?;

    // Register gauges
    gauge!("omega_active_sessions").set(0.0);
    gauge!("omega_cpu_percent").set(0.0);

    tracing::info!("prometheus metrics on :{}", port);
    Ok(())
}

/// Record packet sent.
pub fn record_packet_out(bytes: usize) {
    counter!("omega_packets_out_total").increment(1);
    counter!("omega_bytes_out_total").increment(bytes as u64);
}

/// Record packet received.
pub fn record_packet_in(bytes: usize) {
    counter!("omega_packets_in_total").increment(1);
    counter!("omega_bytes_in_total").increment(bytes as u64);
}

/// Update active session gauge.
pub fn update_session_count(count: usize) {
    gauge!("omega_active_sessions").set(count as f64);
}
