mod datapath;
mod handshake;
mod metrics;
mod morphing;
mod session;

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

/// Default server configuration.
const DEFAULT_BIND: &str = "0.0.0.0:51820";
const DEFAULT_TUN_IP: &str = "10.7.0.1";
const DEFAULT_TUN_PREFIX: u8 = 24;
const DEFAULT_MTU: u16 = 1200;
const DEFAULT_METRICS_PORT: u16 = 9090;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("omega-server v{} starting", env!("CARGO_PKG_VERSION"));

    // Parse env config
    let bind_addr = std::env::var("OMEGA_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let metrics_port: u16 = std::env::var("OMEGA_METRICS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_METRICS_PORT);

    // Initialize metrics
    if let Err(e) = metrics::init_metrics(metrics_port) {
        tracing::warn!("failed to init metrics: {}, continuing without", e);
    }

    // Create TUN device via DeviceBuilder
    tracing::info!(
        "creating TUN device at {} with MTU {}",
        DEFAULT_TUN_IP,
        DEFAULT_MTU
    );

    let tun: Arc<tun_rs::AsyncDevice> = match tun_rs::DeviceBuilder::new()
        .ipv4(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX, None)
        .mtu(DEFAULT_MTU)
        .build_async()
    {
        Ok(dev) => {
            tracing::info!("TUN device created successfully");
            Arc::new(dev)
        }
        Err(e) => {
            tracing::error!("failed to create TUN device: {}", e);
            tracing::error!(
                "ensure you have NET_ADMIN capability \
                (root or Docker with --cap-add=NET_ADMIN)"
            );
            return Err(e.into());
        }
    };

    // Bind UDP socket
    let udp = Arc::new(tokio::net::UdpSocket::bind(&bind_addr).await?);
    tracing::info!("listening on UDP {}", bind_addr);

    // Session manager
    let session_manager = Arc::new(session::SessionManager::new());
    let sessions = session_manager.shared();

    // Spawn cleanup task
    let cleanup_sessions = sessions.clone();
    tokio::spawn(async move {
        session::spawn_cleanup_task(cleanup_sessions).await;
    });

    // Spawn data path tasks
    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let sessions_r = sessions.clone();
    tokio::spawn(async move {
        datapath::tun_to_udp_loop(tun_r, udp_r, sessions_r).await;
    });

    let tun_w = tun.clone();
    let udp_w = udp.clone();
    let sessions_w = sessions.clone();
    let sm = session_manager.clone();
    tokio::spawn(async move {
        datapath::udp_to_tun_loop(tun_w, udp_w, sessions_w, sm, DEFAULT_MTU).await;
    });

    tracing::info!("data path running, press Ctrl+C to stop");

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    tracing::info!(
        "shutting down, {} active sessions",
        session_manager.count()
    );

    Ok(())
}
