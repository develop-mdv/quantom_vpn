mod datapath;
mod handshake;
mod identity;
mod metrics;
mod morphing;
mod session;
mod web_admin;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use identity::{
    ensure_identity_file, parse_platform, IdentityStore, DEFAULT_MAX_CONCURRENT_SESSIONS,
    DEFAULT_MAX_DEVICES,
};

const DEFAULT_BIND: &str = "0.0.0.0:51820";
const DEFAULT_TUN_IP: &str = "10.7.0.1";
const DEFAULT_TUN_PREFIX: u8 = 16;
const DEFAULT_MTU: u16 = 1200;
const DEFAULT_METRICS_PORT: u16 = 9090;
const DEFAULT_SESSION_SNAPSHOT_PATH: &str = "state/sessions.json";
const DEFAULT_ADMIN_COMMAND_PATH: &str = "state/admin_commands.ndjson";
const DEFAULT_ADMIN_WEB_BIND: &str = "127.0.0.1:8081";

#[derive(Debug, Deserialize, Serialize)]
struct AdminCommand {
    command: String,
    flow_id: Option<String>,
    actor: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    command: String,
    ok: bool,
    message: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().collect::<Vec<_>>();
    if args.len() >= 2 && args[1] == "admin" {
        args.drain(0..2);
        return run_admin(args);
    }

    run_server().await
}

async fn run_server() -> anyhow::Result<()> {
    tracing::info!("omega-server v{} starting", env!("CARGO_PKG_VERSION"));

    let bind_addr = std::env::var("OMEGA_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let metrics_port: u16 = std::env::var("OMEGA_METRICS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_METRICS_PORT);
    let allow_legacy_v1 = env_bool("OMEGA_ALLOW_LEGACY_V1");

    if let Err(e) = metrics::init_metrics(metrics_port) {
        tracing::warn!(error = %e, "failed to init metrics, continuing without exporter");
    }

    let identity_path = IdentityStore::default_path();
    ensure_identity_file(&identity_path)?;
    let identity_store = Arc::new(IdentityStore::load(identity_path)?);

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
        Ok(dev) => Arc::new(dev),
        Err(e) => {
            tracing::error!(error = %e, "failed to create TUN device");
            return Err(e.into());
        }
    };

    let udp = Arc::new(tokio::net::UdpSocket::bind(&bind_addr).await?);
    tracing::info!(%bind_addr, "listening on UDP");

    let session_manager = Arc::new(session::SessionManager::new());

    let web_admin_bind = std::env::var("OMEGA_ADMIN_WEB_BIND")
        .unwrap_or_else(|_| DEFAULT_ADMIN_WEB_BIND.to_string());
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

    let admin_command_path = std::env::var("OMEGA_ADMIN_COMMANDS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ADMIN_COMMAND_PATH));
    let command_manager = session_manager.clone();
    let command_identity = identity_store.clone();
    tokio::spawn(async move {
        if let Err(err) =
            spawn_admin_command_task(command_manager, command_identity, admin_command_path).await
        {
            tracing::warn!(error = %err, "admin command task stopped");
        }
    });

    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let sessions_r = session_manager.clone();
    tokio::spawn(async move {
        datapath::tun_to_udp_loop(tun_r, udp_r, sessions_r).await;
    });

    let tun_w = tun.clone();
    let udp_w = udp.clone();
    let sessions_w = session_manager.clone();
    let identity_w = identity_store.clone();
    tokio::spawn(async move {
        datapath::udp_to_tun_loop(
            tun_w,
            udp_w,
            sessions_w,
            identity_w,
            DEFAULT_MTU,
            allow_legacy_v1,
        )
        .await;
    });

    tracing::info!("data path running, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    tracing::info!(active_sessions = session_manager.count(), "shutting down");

    Ok(())
}

fn run_admin(args: Vec<String>) -> anyhow::Result<()> {
    let identity_path = IdentityStore::default_path();
    ensure_identity_file(&identity_path)?;
    let store = IdentityStore::load(identity_path)?;

    if args.is_empty() {
        print_admin_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "create_user" => {
            let max_devices = arg_value(&args, "--max-devices")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(DEFAULT_MAX_DEVICES);
            let max_sessions = arg_value(&args, "--max-sessions")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(DEFAULT_MAX_CONCURRENT_SESSIONS);
            let user = store.create_user(max_devices, max_sessions, "admin_cli")?;
            println!(
                "created user: user_id={} max_devices={} max_concurrent_sessions={}",
                user.user_id, user.max_devices, user.max_concurrent_sessions
            );
        }
        "list_users" => {
            for user in store.list_users() {
                println!(
                    "user_id={} status={:?} max_devices={} max_concurrent_sessions={}",
                    user.user_id, user.status, user.max_devices, user.max_concurrent_sessions
                );
            }
        }
        "block_user" => {
            let user_id = required_arg(&args, "--user-id")?;
            let user = store.block_user(user_id, "admin_cli")?;
            println!("blocked user {}", user.user_id);
        }
        "unblock_user" => {
            let user_id = required_arg(&args, "--user-id")?;
            let user = store.unblock_user(user_id, "admin_cli")?;
            println!("unblocked user {}", user.user_id);
        }
        "delete_user" => {
            let user_id = required_arg(&args, "--user-id")?;
            let user = store.delete_user(user_id, "admin_cli")?;
            println!("deleted user {}", user.user_id);
        }
        "register_device" => {
            let user_id = required_arg(&args, "--user-id")?;
            let device_name = required_arg(&args, "--device-name")?;
            let platform = parse_platform(required_arg(&args, "--platform")?)?;
            let fingerprint = arg_value(&args, "--fingerprint").unwrap_or("manual");

            let registered =
                store.register_device(user_id, device_name, platform, fingerprint, "admin_cli")?;

            println!(
                "registered device: device_id={} user_id={} platform={} token={}",
                registered.device.device_id,
                registered.device.user_id,
                registered.device.platform.as_str(),
                registered.device_token
            );
        }
        "revoke_device" => {
            let device_id = required_arg(&args, "--device-id")?;
            let device = store.revoke_device(device_id, "admin_cli")?;
            println!("revoked device {}", device.device_id);
        }
        "list_user_devices" => {
            let user_id = required_arg(&args, "--user-id")?;
            for device in store.list_user_devices(user_id) {
                println!(
                    "device_id={} user_id={} name={} platform={} revoked={} last_seen={:?}",
                    device.device_id,
                    device.user_id,
                    device.device_name,
                    device.platform.as_str(),
                    device.revoked,
                    device.last_seen_at
                );
            }
        }
        "list_active_sessions" => {
            let snapshot_path = std::env::var("OMEGA_SESSION_SNAPSHOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(DEFAULT_SESSION_SNAPSHOT_PATH));
            let raw = fs::read_to_string(&snapshot_path).with_context(|| {
                format!(
                    "failed to read session snapshot {} (is server running?)",
                    snapshot_path.display()
                )
            })?;
            println!("{}", raw);
        }
        "terminate_session" => {
            let flow_id = required_arg(&args, "--flow-id")?;
            enqueue_admin_command(AdminCommand {
                command: "terminate_session".to_string(),
                flow_id: Some(flow_id.to_string()),
                actor: Some("admin_cli".to_string()),
            })?;
            println!("queued terminate_session for flow_id={}", flow_id);
        }
        "show_audit" => {
            let limit = arg_value(&args, "--limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(50);
            for event in store.recent_audit(limit) {
                println!(
                    "ts={} action={} actor={} details={}",
                    event.ts, event.action, event.actor, event.details
                );
            }
        }
        _ => {
            print_admin_usage();
            return Err(anyhow!("unknown admin command '{}'", args[0]));
        }
    }

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

async fn spawn_admin_command_task(
    session_manager: Arc<session::SessionManager>,
    identity_store: Arc<IdentityStore>,
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

            let result = execute_admin_command(&session_manager, &identity_store, cmd);
            tracing::info!(
                command = %result.command,
                ok = result.ok,
                message = %result.message,
                "admin command processed"
            );
        }

        processed_lines = lines.len();
    }
}

fn execute_admin_command(
    session_manager: &session::SessionManager,
    identity_store: &IdentityStore,
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

            let ok = session_manager.terminate_session(&flow_id);
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
        _ => CommandResult {
            command: cmd.command,
            ok: false,
            message: "unknown command".to_string(),
        },
    }
}

fn enqueue_admin_command(command: AdminCommand) -> anyhow::Result<()> {
    let command_path = std::env::var("OMEGA_ADMIN_COMMANDS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ADMIN_COMMAND_PATH));
    if let Some(parent) = command_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let line = serde_json::to_string(&command)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&command_path)
        .with_context(|| format!("failed to open {}", command_path.display()))?;
    writeln!(file, "{}", line)?;
    Ok(())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn required_arg<'a>(args: &'a [String], flag: &str) -> anyhow::Result<&'a str> {
    arg_value(args, flag).ok_or_else(|| anyhow!("missing required argument {}", flag))
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn print_admin_usage() {
    println!("omega-server admin commands:");
    println!("  create_user [--max-devices N] [--max-sessions N]");
    println!("  list_users");
    println!("  block_user --user-id <uuid>");
    println!("  unblock_user --user-id <uuid>");
    println!("  delete_user --user-id <uuid>");
    println!("  register_device --user-id <uuid> --device-name <name> --platform <windows|linux|macos|android|ios|other> [--fingerprint <value>]");
    println!("  revoke_device --device-id <uuid>");
    println!("  list_user_devices --user-id <uuid>");
    println!("  list_active_sessions");
    println!("  terminate_session --flow-id <32_hex_chars>");
    println!("  show_audit [--limit N]");
}
