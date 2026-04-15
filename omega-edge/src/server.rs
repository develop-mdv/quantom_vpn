use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{datapath, fabric, handshake, metrics, observability, runtime, session, web_admin};

use omega_control::control_plane::{FabricNodeRecord, FabricNodeRole};
use omega_control::identity::{ensure_identity_file, IdentityStore};
use omega_core_wire::TOTAL_OVERHEAD;

const DEFAULT_BIND: &str = "0.0.0.0:51820";
const DEFAULT_TUN_IP: &str = "10.7.0.1";
const DEFAULT_TUN_PREFIX: u8 = 16;
const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9090";
const DEFAULT_SESSION_SNAPSHOT_PATH: &str = "state/sessions.json";
const DEFAULT_ADMIN_COMMAND_PATH: &str = "state/admin_commands.ndjson";
const DEFAULT_ADMIN_WEB_BIND: &str = "127.0.0.1:8081";
const DEFAULT_UDP_RCVBUF: usize = 8 * 1024 * 1024;
const DEFAULT_UDP_SNDBUF: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
struct AdminCommand {
    command: String,
    flow_id: Option<String>,
    actor: Option<String>,
    node_id: Option<String>,
    healthy: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    command: String,
    ok: bool,
    message: String,
}

pub async fn run_server() -> anyhow::Result<()> {
    tracing::info!("omega-server v{} starting", env!("CARGO_PKG_VERSION"));

    let profile = runtime::ServerProfile::from_env();
    let morphing_policy = runtime::morphing_policy_from_env(profile);
    let session_admission = runtime::default_session_admission(profile);
    let persona = omega_stealth::PersonaId::from_env(runtime::default_persona(profile));
    let bind_addr = std::env::var("OMEGA_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let metrics_bind =
        std::env::var("OMEGA_METRICS_BIND").unwrap_or_else(|_| DEFAULT_METRICS_BIND.to_string());
    let web_admin_bind = std::env::var("OMEGA_ADMIN_WEB_BIND")
        .unwrap_or_else(|_| DEFAULT_ADMIN_WEB_BIND.to_string());
    let udp_rcvbuf = env_usize("OMEGA_UDP_RCVBUF", DEFAULT_UDP_RCVBUF);
    let udp_sndbuf = env_usize("OMEGA_UDP_SNDBUF", DEFAULT_UDP_SNDBUF);
    let allow_legacy_v1 = env_bool("OMEGA_ALLOW_LEGACY_V1");
    let tunnel_mtu = std::env::var("OMEGA_TUN_MTU")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .map(|value| value.clamp(1200, 1420))
        .unwrap_or_else(|| profile.default_mtu());

    if let Err(e) = metrics::init_metrics(&metrics_bind) {
        tracing::warn!(error = %e, "failed to init metrics, continuing without exporter");
    }

    let identity_path = IdentityStore::default_path();
    ensure_identity_file(&identity_path)?;
    let identity_store = Arc::new(IdentityStore::load(identity_path)?);
    identity_store.ensure_bootstrap_policy(session_admission.clone(), "server_bootstrap")?;

    tracing::info!(
        "creating TUN device at {} with MTU {}",
        DEFAULT_TUN_IP,
        tunnel_mtu
    );

    // Reduce TUN MTU so every IP packet fits in a single transport
    // datagram without fragmentation (wire overhead = 62 bytes).
    let safe_tun_mtu =
        (tunnel_mtu as usize).saturating_sub(TOTAL_OVERHEAD + 13).clamp(576, 1500) as u16;
    let tun: Arc<tun_rs::AsyncDevice> = match tun_rs::DeviceBuilder::new()
        .ipv4(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX, None)
        .mtu(safe_tun_mtu)
        .build_async()
    {
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            tracing::error!(error = %e, "failed to create TUN device");
            return Err(e.into());
        }
    };

    let udp = Arc::new(bind_udp_socket(&bind_addr, udp_rcvbuf, udp_sndbuf)?);
    tracing::info!(%bind_addr, udp_rcvbuf, udp_sndbuf, "listening on UDP");

    let session_manager = Arc::new(session::SessionManager::with_control_plane(
        identity_store.clone(),
    ));
    let handshake_service = Arc::new(handshake::HandshakeService::new());
    let fabric = fabric::FabricController::shared(omega_relay::RelayRole::Edge, &session_admission);
    sync_fabric_graph_into_control_plane(&identity_store, &fabric.read().unwrap())?;
    let fabric_view = fabric.read().unwrap().runtime_view();
    let runtime_config = runtime::ServerRuntimeConfig {
        profile,
        mode: session_admission.mode,
        morphing_policy,
        persona,
        node_role: fabric_view.local_role.clone(),
        fabric_node_id: fabric_view.local_node_id.clone(),
        fabric_region: fabric_view.region.clone(),
        bind_addr: bind_addr.clone(),
        metrics_bind: metrics_bind.clone(),
        admin_web_bind: web_admin_bind.clone(),
        tunnel_ip: DEFAULT_TUN_IP.to_string(),
        tunnel_prefix: DEFAULT_TUN_PREFIX,
        tunnel_mtu,
        udp_rcvbuf,
        udp_sndbuf,
        transport: "udp".to_string(),
        tunnel_family: "ipv4".to_string(),
        ipv6_mode: runtime::Ipv6Mode::Disabled,
        allow_legacy_v1,
    };
    let observability_config = observability::ObservabilityConfig::from_env();
    observability::init_trace_journal(observability_config.trace_journal_path.clone())?;
    observability::record_trace_event(
        "server",
        "info",
        "server-bootstrap",
        None,
        "server bootstrap completed",
        serde_json::json!({
            "bind_addr": bind_addr,
            "metrics_bind": metrics_bind,
            "admin_web_bind": web_admin_bind,
            "fabric_node_id": fabric_view.local_node_id,
            "fabric_region": fabric_view.region,
            "profile": format!("{:?}", profile).to_ascii_lowercase(),
            "mode": format!("{:?}", session_admission.mode).to_ascii_lowercase(),
            "persona": persona.label(),
            "allow_legacy_v1": allow_legacy_v1,
        }),
    );

    if !env_bool("OMEGA_ADMIN_WEB_DISABLE") {
        let web_identity = identity_store.clone();
        let web_sessions = session_manager.clone();
        tokio::spawn(async move {
            if let Err(err) = web_admin::run(web_admin_bind, web_identity, web_sessions).await {
                tracing::warn!(error = %err, "web admin stopped");
            }
        });
    }

    let cleanup_manager = session_manager.clone();
    tokio::spawn(async move {
        session::spawn_cleanup_task(cleanup_manager).await;
    });

    let snapshot_path = std::env::var("OMEGA_SESSION_SNAPSHOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SESSION_SNAPSHOT_PATH));
    let snapshot_manager = session_manager.clone();
    tokio::spawn(async move {
        if let Err(err) = spawn_session_snapshot_task(snapshot_manager, snapshot_path).await {
            tracing::warn!(error = %err, "session snapshot task stopped");
        }
    });

    let runtime_snapshot_path = runtime::ServerRuntimeConfig::runtime_snapshot_path();
    let runtime_sessions = session_manager.clone();
    let runtime_details = runtime_config.clone();
    let runtime_fabric = fabric.clone();
    tokio::spawn(async move {
        if let Err(err) = runtime::spawn_runtime_snapshot_task(
            runtime_details,
            runtime_sessions,
            runtime_fabric,
            runtime_snapshot_path,
        )
        .await
        {
            tracing::warn!(error = %err, "runtime snapshot task stopped");
        }
    });

    let observability_sessions = session_manager.clone();
    let observability_identity = identity_store.clone();
    let observability_fabric = fabric.clone();
    let observability_handshake = handshake_service.clone();
    let observability_details = observability_config.clone();
    tokio::spawn(async move {
        if let Err(err) = observability::spawn_observability_task(
            observability_details,
            observability_sessions,
            observability_identity,
            observability_fabric,
            observability_handshake,
        )
        .await
        {
            tracing::warn!(error = %err, "observability task stopped");
        }
    });

    let admin_command_path = std::env::var("OMEGA_ADMIN_COMMANDS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ADMIN_COMMAND_PATH));
    let command_manager = session_manager.clone();
    let command_identity = identity_store.clone();
    let command_fabric = fabric.clone();
    let command_admission = session_admission.clone();
    tokio::spawn(async move {
        if let Err(err) = spawn_admin_command_task(
            command_manager,
            command_identity,
            command_fabric,
            command_admission,
            admin_command_path,
        )
        .await
        {
            tracing::warn!(error = %err, "admin command task stopped");
        }
    });

    let reconcile_sessions = session_manager.clone();
    let reconcile_identity = identity_store.clone();
    let reconcile_fabric = fabric.clone();
    tokio::spawn(async move {
        spawn_fabric_reconcile_task(reconcile_sessions, reconcile_identity, reconcile_fabric).await;
    });

    let control_sessions = session_manager.clone();
    let control_identity = identity_store.clone();
    tokio::spawn(async move {
        spawn_control_plane_reconcile_task(control_sessions, control_identity).await;
    });

    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let sessions_r = session_manager.clone();
    tokio::spawn(async move {
        loop {
            let tun_c = tun_r.clone();
            let udp_c = udp_r.clone();
            let sessions_c = sessions_r.clone();
            let handle = tokio::spawn(async move {
                datapath::tun_to_udp_loop(tun_c, udp_c, sessions_c).await;
            });
            match handle.await {
                Ok(()) => {
                    tracing::warn!("tun_to_udp_loop exited unexpectedly, restarting in 1s");
                }
                Err(err) => {
                    tracing::error!(error = %err, "tun_to_udp_loop panicked, restarting in 1s");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    let tun_w = tun.clone();
    let udp_w = udp.clone();
    let sessions_w = session_manager.clone();
    let identity_w = identity_store.clone();
    let handshake_w = handshake_service.clone();
    let fabric_w = fabric.clone();
    let admission_w = session_admission.clone();
    tokio::spawn(async move {
        loop {
            let tun_c = tun_w.clone();
            let udp_c = udp_w.clone();
            let sessions_c = sessions_w.clone();
            let identity_c = identity_w.clone();
            let handshake_c = handshake_w.clone();
            let admission_c = admission_w.clone();
            let fabric_c = fabric_w.clone();
            let handle = tokio::spawn(async move {
                datapath::udp_to_tun_loop(
                    tun_c,
                    udp_c,
                    sessions_c,
                    identity_c,
                    handshake_c,
                    tunnel_mtu,
                    allow_legacy_v1,
                    morphing_policy,
                    persona,
                    &admission_c,
                    &fabric_c,
                )
                .await;
            });
            match handle.await {
                Ok(()) => {
                    tracing::warn!("udp_to_tun_loop exited unexpectedly, restarting in 1s");
                }
                Err(err) => {
                    tracing::error!(error = %err, "udp_to_tun_loop panicked, restarting in 1s");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    tracing::info!("data path running, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    observability::record_trace_event(
        "server",
        "warning",
        "server-shutdown",
        None,
        "server received shutdown signal",
        serde_json::json!({
            "active_sessions": session_manager.count(),
        }),
    );
    tracing::info!(active_sessions = session_manager.count(), "shutting down");

    Ok(())
}

async fn spawn_session_snapshot_task(
    session_manager: Arc<session::SessionManager>,
    path: PathBuf,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let snapshot = session_manager.snapshot();
        let payload = serde_json::to_string_pretty(&snapshot)?;
        tokio::fs::write(&path, payload).await?;
    }
}

async fn spawn_fabric_reconcile_task(
    session_manager: Arc<session::SessionManager>,
    identity_store: Arc<IdentityStore>,
    fabric: fabric::SharedFabric,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        interval.tick().await;
        for flow_id in session_manager.flow_ids() {
            let outcome = {
                let mut session = match session_manager.get(&flow_id) {
                    Some(session) => session,
                    None => continue,
                };
                fabric.read().unwrap().reconcile_session(&mut session)
            };

            if let Some(decision) = outcome {
                let flow_hex = session::flow_id_to_hex(&flow_id);
                metrics::record_fabric_failover(decision.within_budget);
                observability::record_trace_event(
                    "fabric",
                    if decision.within_budget {
                        "warning"
                    } else {
                        "critical"
                    },
                    observability::session_correlation_id(&flow_hex),
                    Some(flow_hex.clone()),
                    "fabric failover applied during reconcile",
                    serde_json::json!({
                        "previous_route_id": decision.previous_route_id,
                        "active_route_id": decision.active_route.route_id,
                        "reason": format!("{:?}", decision.reason).to_ascii_lowercase(),
                        "reroute_time_ms": decision.reroute_time_ms,
                        "within_budget": decision.within_budget,
                        "backup_routes": decision.backup_routes.iter().map(|route| route.route_id.clone()).collect::<Vec<_>>(),
                    }),
                );
                let _ = identity_store.update_session_route(
                    &flow_hex,
                    &decision.active_route.route_id,
                    decision
                        .backup_routes
                        .iter()
                        .map(|route| route.route_id.clone())
                        .collect(),
                    0.0,
                    decision.handoff_ticket.generation,
                    "fabric_reconcile",
                );
                identity_store.append_audit(
                    "fabric_failover",
                    "fabric_reconcile",
                    serde_json::json!({
                        "flow_id": flow_hex,
                        "previous_route_id": decision.previous_route_id,
                        "active_route_id": decision.active_route.route_id,
                        "reason": format!("{:?}", decision.reason).to_ascii_lowercase(),
                        "reroute_time_ms": decision.reroute_time_ms,
                        "within_budget": decision.within_budget,
                    }),
                );
            }
        }
    }
}

async fn spawn_admin_command_task(
    session_manager: Arc<session::SessionManager>,
    identity_store: Arc<IdentityStore>,
    fabric: fabric::SharedFabric,
    admission: omega_control::policy::SessionAdmission,
    path: PathBuf,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if !path.exists() {
        tokio::fs::write(&path, "").await?;
    }

    let mut processed_lines = 0usize;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        interval.tick().await;
        let raw = match tokio::fs::read_to_string(&path).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "failed to read admin command file"
                );
                continue;
            }
        };

        let lines = raw.lines().collect::<Vec<_>>();
        if lines.len() < processed_lines {
            processed_lines = 0;
        }

        for line in lines.iter().skip(processed_lines) {
            if line.trim().is_empty() {
                continue;
            }

            let cmd: AdminCommand = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(error = %err, line = %line, "invalid admin command line");
                    continue;
                }
            };

            let command_name = cmd.command.clone();
            let flow_id = cmd.flow_id.clone();
            let node_id = cmd.node_id.clone();
            let actor = cmd.actor.clone();
            let result =
                execute_admin_command(&session_manager, &identity_store, &fabric, &admission, cmd);
            tracing::info!(
                command = %result.command,
                ok = result.ok,
                message = %result.message,
                "admin command processed"
            );
            let correlation_id = flow_id
                .as_deref()
                .map(observability::session_correlation_id)
                .unwrap_or_else(|| format!("admin-{}", command_name));
            observability::record_trace_event(
                "admin",
                if result.ok { "info" } else { "warning" },
                correlation_id,
                flow_id,
                "admin command processed",
                serde_json::json!({
                    "command": command_name,
                    "ok": result.ok,
                    "message": result.message,
                    "node_id": node_id,
                    "actor": actor,
                }),
            );
        }

        processed_lines = lines.len();
    }
}

fn execute_admin_command(
    session_manager: &session::SessionManager,
    identity_store: &IdentityStore,
    fabric: &fabric::SharedFabric,
    admission: &omega_control::policy::SessionAdmission,
    cmd: AdminCommand,
) -> CommandResult {
    match cmd.command.as_str() {
        "terminate_session" => {
            let Some(flow) = cmd.flow_id.as_deref() else {
                return CommandResult {
                    command: cmd.command,
                    ok: false,
                    message: "flow_id is required".to_string(),
                };
            };

            let Some(flow_id) = session::flow_id_from_hex(flow) else {
                return CommandResult {
                    command: cmd.command,
                    ok: false,
                    message: format!("invalid flow_id {}", flow),
                };
            };

            let ok = session_manager.terminate_session_with_reason(&flow_id, "admin_command");
            identity_store.append_audit(
                "terminate_session",
                cmd.actor.as_deref().unwrap_or("admin_api"),
                serde_json::json!({
                    "flow_id": flow,
                    "terminated": ok,
                }),
            );

            CommandResult {
                command: cmd.command,
                ok,
                message: if ok {
                    format!("terminated {}", flow)
                } else {
                    format!("session {} not found", flow)
                },
            }
        }
        "fabric_mark_node" => {
            let Some(node_id) = cmd.node_id.as_deref() else {
                return CommandResult {
                    command: cmd.command,
                    ok: false,
                    message: "node_id is required".to_string(),
                };
            };
            let healthy = cmd.healthy.unwrap_or(false);
            let ok = fabric
                .write()
                .unwrap()
                .mark_node(node_id, healthy, admission);
            if ok {
                metrics::record_fabric_operator_action();
                let _ = identity_store.mark_fabric_node(
                    node_id,
                    healthy,
                    cmd.actor.as_deref().unwrap_or("admin_api"),
                );
                identity_store.append_audit(
                    "fabric_mark_node",
                    cmd.actor.as_deref().unwrap_or("admin_api"),
                    serde_json::json!({
                        "node_id": node_id,
                        "healthy": healthy,
                    }),
                );
            }
            CommandResult {
                command: cmd.command,
                ok,
                message: if ok {
                    format!("fabric node {} set healthy={}", node_id, healthy)
                } else {
                    format!("fabric node {} not found", node_id)
                },
            }
        }
        _ => CommandResult {
            command: cmd.command,
            ok: false,
            message: "unknown command".to_string(),
        },
    }
}

async fn spawn_control_plane_reconcile_task(
    session_manager: Arc<session::SessionManager>,
    identity_store: Arc<IdentityStore>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        for flow_id in session_manager.flow_ids() {
            let flow_hex = session::flow_id_to_hex(&flow_id);
            if let Some(reason) = identity_store.should_terminate_session(&flow_hex) {
                let terminated = session_manager.terminate_session_with_reason(&flow_id, &reason);
                if terminated {
                    observability::record_trace_event(
                        "control_plane",
                        "warning",
                        observability::session_correlation_id(&flow_hex),
                        Some(flow_hex.clone()),
                        "control plane terminated session",
                        serde_json::json!({
                            "reason": reason,
                        }),
                    );
                }
            }
        }
    }
}

fn sync_fabric_graph_into_control_plane(
    identity_store: &IdentityStore,
    controller: &fabric::FabricController,
) -> anyhow::Result<()> {
    for node in controller.graph().nodes.values() {
        let role = match node.role {
            omega_relay::RelayRole::Edge => FabricNodeRole::Edge,
            omega_relay::RelayRole::Relay => FabricNodeRole::Relay,
            omega_relay::RelayRole::Exit => FabricNodeRole::Exit,
        };
        identity_store.upsert_fabric_node(
            FabricNodeRecord {
                node_id: node.node_id.clone(),
                role,
                region: node.region.clone(),
                operator: node.operator.clone(),
                graph_revision: controller.graph().revision,
                healthy: node.health.healthy,
                operational_percent: node.health.operational_percent,
                trust_label: format!("{:?}", node.trust_zone).to_ascii_lowercase(),
                last_seen_at: omega_control::identity::now_ts(),
                consistency: omega_control::control_plane::ConsistencyLevel::Eventual,
            },
            "fabric_bootstrap",
        )?;
    }
    Ok(())
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn bind_udp_socket(
    bind_addr: &str,
    recv_buffer: usize,
    send_buffer: usize,
) -> anyhow::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: SocketAddr = bind_addr
        .parse()
        .with_context(|| format!("invalid OMEGA_BIND address '{}'", bind_addr))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("failed to create UDP socket for {}", bind_addr))?;
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;
    let _ = socket.set_reuse_address(true);
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_recv_buffer_size(recv_buffer);
    let _ = socket.set_send_buffer_size(send_buffer);
    socket
        .bind(&addr.into())
        .with_context(|| format!("failed to bind UDP socket to {}", bind_addr))?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket).context("failed to convert UDP socket for tokio")
}
