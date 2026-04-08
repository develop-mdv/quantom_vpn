use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use omega_control::identity::{
    ensure_identity_file, parse_platform, IdentityStore, DEFAULT_MAX_CONCURRENT_SESSIONS,
    DEFAULT_MAX_DEVICES,
};

const DEFAULT_ADMIN_COMMAND_PATH: &str = "state/admin_commands.ndjson";

#[derive(Debug, Deserialize, Serialize)]
struct AdminCommand {
    command: String,
    flow_id: Option<String>,
    actor: Option<String>,
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

    omega_edge::run_server().await
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
            for session in store.list_active_sessions() {
                println!(
                    "flow_id={} user_id={} device_id={} tunnel_ip={} peer={} policy_id={} mode={:?} status={:?} route={} last_seen={}",
                    session.flow_id,
                    session.user_id,
                    session.device_id,
                    session.tunnel_ip,
                    session.client_addr,
                    session.policy_id,
                    session.mode,
                    session.status,
                    session.active_route_id,
                    session.last_seen_at
                );
            }
        }
        "show_control_plane" => {
            let summary = store.summary();
            println!(
                "revision={} users={} blocked_users={} active_devices={} revoked_devices={} active_sessions={} issued_tickets={} policies={} fabric_nodes={}",
                summary.revision,
                summary.users,
                summary.blocked_users,
                summary.active_devices,
                summary.revoked_devices,
                summary.active_sessions,
                summary.issued_tickets,
                summary.policies,
                summary.fabric_nodes
            );
        }
        "list_policies" => {
            for policy in store.list_policies() {
                println!(
                    "policy_id={} version={} enabled={} rules={} updated_at={}",
                    policy.policy_id,
                    policy.version,
                    policy.enabled,
                    policy.rules.len(),
                    policy.updated_at
                );
            }
        }
        "show_policy_conflicts" => {
            for conflict in store.policy_conflicts() {
                println!(
                    "policy_id={} field={} left={} right={} reason={}",
                    conflict.policy_id,
                    conflict.field,
                    conflict.left_rule_id,
                    conflict.right_rule_id,
                    conflict.reason
                );
            }
        }
        "list_fabric_nodes" => {
            for node in store.list_fabric_nodes() {
                println!(
                    "node_id={} role={} region={} operator={} healthy={} revision={} trust={}",
                    node.node_id,
                    node.role.as_str(),
                    node.region,
                    node.operator,
                    node.healthy,
                    node.graph_revision,
                    node.trust_label
                );
            }
        }
        "rotate_device_token" => {
            let device_id = required_arg(&args, "--device-id")?;
            let rotated = store.rotate_device_token(device_id, "admin_cli")?;
            println!(
                "rotated device token: device_id={} user_id={} token={}",
                rotated.device.device_id, rotated.device.user_id, rotated.device_token
            );
        }
        "show_runtime" => {
            let snapshot_path = omega_edge::runtime::ServerRuntimeConfig::runtime_snapshot_path();
            let raw = fs::read_to_string(&snapshot_path).with_context(|| {
                format!(
                    "failed to read runtime snapshot {} (is server running?)",
                    snapshot_path.display()
                )
            })?;
            println!("{}", raw);
        }
        "show_observability" => {
            let snapshot_path = omega_edge::observability::ObservabilityConfig::snapshot_path();
            let raw = fs::read_to_string(&snapshot_path).with_context(|| {
                format!(
                    "failed to read observability snapshot {} (is server running?)",
                    snapshot_path.display()
                )
            })?;
            println!("{}", raw);
        }
        "show_rollout_guard" => {
            let snapshot_path = omega_edge::observability::ObservabilityConfig::snapshot_path();
            let snapshot = omega_edge::observability::load_observability_snapshot(&snapshot_path)?
                .ok_or_else(|| {
                    anyhow!(
                        "observability snapshot {} is not available yet",
                        snapshot_path.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&snapshot.rollout_guard)?);
        }
        "assert_rollout_guard" => {
            let snapshot_path = omega_edge::observability::ObservabilityConfig::snapshot_path();
            let guard = omega_edge::observability::assert_rollout_guard(&snapshot_path)?;
            println!("{}", serde_json::to_string_pretty(&guard)?);
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

fn print_admin_usage() {
    println!("omega-server admin commands:");
    println!("  create_user [--max-devices N] [--max-sessions N]");
    println!("  list_users");
    println!("  block_user --user-id <uuid>");
    println!("  unblock_user --user-id <uuid>");
    println!("  delete_user --user-id <uuid>");
    println!("  register_device --user-id <uuid> --device-name <name> --platform <windows|linux|macos|android|ios|other> [--fingerprint <value>]");
    println!("  revoke_device --device-id <uuid>");
    println!("  rotate_device_token --device-id <uuid>");
    println!("  list_user_devices --user-id <uuid>");
    println!("  list_active_sessions");
    println!("  show_control_plane");
    println!("  list_policies");
    println!("  show_policy_conflicts");
    println!("  list_fabric_nodes");
    println!("  show_runtime");
    println!("  show_observability");
    println!("  show_rollout_guard");
    println!("  assert_rollout_guard");
    println!("  terminate_session --flow-id <32_hex_chars>");
    println!("  show_audit [--limit N]");
}
