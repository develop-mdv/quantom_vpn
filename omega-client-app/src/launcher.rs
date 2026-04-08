use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use omega_client_runtime::{
    load_diagnostics_snapshot, load_lifecycle_snapshot, write_runtime_command,
    ClientDiagnosticsSnapshot, ClientLifecycleSnapshot, ClientLifecycleState, RuntimeControlAction,
};
use serde::Serialize;
use tokio::time::sleep;

use crate::app_config::{profile_label, DesktopAppConfig};

#[derive(Debug, Clone, Serialize)]
pub struct DesktopStatus {
    pub runtime_pid: Option<u32>,
    pub runtime_running: bool,
    pub lifecycle: Option<ClientLifecycleSnapshot>,
    pub diagnostics: Option<ClientDiagnosticsSnapshot>,
}

pub async fn connect(config: &DesktopAppConfig) -> anyhow::Result<DesktopStatus> {
    config.ensure_ready()?;

    let existing = status(config)?;
    if existing.runtime_running {
        return Ok(existing);
    }

    if let Some(parent) = config.pid_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create client state directory {}",
                parent.display()
            )
        })?;
    }
    let _ = std::fs::remove_file(&config.control_path);
    let _ = std::fs::remove_file(&config.lifecycle_path);

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.log_path)
        .with_context(|| format!("failed to open runtime log {}", config.log_path.display()))?;
    let stderr_file = log_file.try_clone()?;

    let current_exe =
        std::env::current_exe().context("failed to resolve omega-client-app binary")?;
    let mut command = Command::new(current_exe);
    command
        .arg("__runtime")
        .env("OMEGA_SERVER", &config.server_endpoint)
        .env("OMEGA_DEVICE_ID", &config.device_id)
        .env("OMEGA_DEVICE_TOKEN", &config.device_token)
        .env("OMEGA_DEVICE_NAME", &config.device_name)
        .env("OMEGA_PROFILE", config.profile.label())
        .env(
            "OMEGA_BACKGROUND_MODE",
            if config.background_mode { "1" } else { "0" },
        )
        .env("OMEGA_DIAGNOSTICS_PATH", &config.diagnostics_path)
        .env("OMEGA_LIFECYCLE_PATH", &config.lifecycle_path)
        .env("OMEGA_CONTROL_PATH", &config.control_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file));

    if let Ok(cwd) = std::env::current_dir() {
        command.current_dir(cwd);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let child = command
        .spawn()
        .context("failed to launch background runtime")?;
    write_pid(&config.pid_path, child.id())?;

    wait_for_runtime_ready(config, Duration::from_secs(20)).await
}

pub async fn disconnect(config: &DesktopAppConfig) -> anyhow::Result<DesktopStatus> {
    let current = status(config)?;
    let Some(pid) = current.runtime_pid.filter(|_| current.runtime_running) else {
        clear_pid(&config.pid_path)?;
        return Ok(status(config)?);
    };

    let _ = write_runtime_command(
        &config.control_path,
        RuntimeControlAction::Stop,
        Some("disconnect requested from omega-client-app".to_string()),
    );

    let deadline = SystemTime::now() + Duration::from_secs(10);
    while is_process_running(pid) && SystemTime::now() < deadline {
        sleep(Duration::from_millis(350)).await;
    }

    if is_process_running(pid) {
        force_kill(pid)?;
    }

    clear_pid(&config.pid_path)?;
    Ok(status(config)?)
}

pub async fn reconnect(config: &DesktopAppConfig) -> anyhow::Result<DesktopStatus> {
    let _ = disconnect(config).await?;
    connect(config).await
}

pub fn status(config: &DesktopAppConfig) -> anyhow::Result<DesktopStatus> {
    let pid = read_pid(&config.pid_path)?;
    let runtime_running = pid.map(is_process_running).unwrap_or(false);
    let lifecycle = load_lifecycle_snapshot(&config.lifecycle_path)?;
    let diagnostics = load_diagnostics_snapshot(&config.diagnostics_path)?;
    Ok(DesktopStatus {
        runtime_pid: pid,
        runtime_running,
        lifecycle,
        diagnostics,
    })
}

pub fn render_status(status: &DesktopStatus, config: &DesktopAppConfig, advanced: bool) -> String {
    let mut lines = Vec::new();

    if status.runtime_running {
        lines.push(format!("State: {}", human_state(status)));
        lines.push(format!("Profile: {}", profile_label(config.profile)));
        lines.push(format!("Server: {}", config.server_endpoint));
        if let Some(lifecycle) = &status.lifecycle {
            lines.push(format!("Runtime message: {}", lifecycle.message));
        }
        if let Some(diag) = &status.diagnostics {
            lines.push(format!(
                "Network: {} | RTT {} ms | Loss {:.1}%",
                diag.path_quality, diag.transport_rtt_ms, diag.estimated_rx_loss_percent
            ));
            if let Some(tunnel_ip) = &diag.tunnel_ip {
                lines.push(format!("Tunnel IP: {tunnel_ip}"));
            }
            if let Some(issue) = &diag.suspected_issue {
                lines.push(format!("Attention: {issue}"));
            }
        } else {
            lines.push("Network: waiting for diagnostics snapshot".to_string());
        }
    } else {
        lines.push(format!("State: {}", human_state(status)));
        lines.push(format!("Profile: {}", profile_label(config.profile)));
        lines.push(format!("Server: {}", config.server_endpoint));
        if let Some(lifecycle) = &status.lifecycle {
            lines.push(format!("Last runtime message: {}", lifecycle.message));
            if let Some(action) = &lifecycle.suggested_action {
                lines.push(format!("Suggested action: {action}"));
            }
        } else {
            lines.push(
                "Runtime is not running. Use `omega-client-app connect` to start it.".to_string(),
            );
        }
    }

    if advanced {
        lines.push(String::new());
        lines.push("Advanced diagnostics:".to_string());
        if let Some(pid) = status.runtime_pid {
            lines.push(format!("Runtime PID: {pid}"));
        }
        if let Some(lifecycle) = &status.lifecycle {
            lines.push(format!("Lifecycle state: {:?}", lifecycle.state));
            lines.push(format!("Background mode: {}", lifecycle.background_mode));
            if let Some(scope) = lifecycle.failure_scope {
                lines.push(format!("Failure scope: {:?}", scope));
            }
            if let Some(error) = &lifecycle.last_error {
                lines.push(format!("Last error: {error}"));
            }
            if let Some(action) = &lifecycle.suggested_action {
                lines.push(format!("Recovery hint: {action}"));
            }
        }
        if let Some(diag) = &status.diagnostics {
            lines.push(format!("Path mode: {}", diag.path_mode));
            lines.push(format!(
                "Path belief: {} ({:.1}% confidence)",
                diag.path_belief, diag.path_belief_confidence_percent
            ));
            lines.push(format!(
                "Persona: {} -> {} | detectability delta {:.1}%",
                diag.configured_persona,
                diag.active_persona,
                diag.persona_detectability_improvement_percent
            ));
            lines.push(format!(
                "Reliability: control={} interactive={} bulk={}",
                diag.reliability_control_strategy,
                diag.reliability_interactive_strategy,
                diag.reliability_bulk_strategy
            ));
            lines.push(format!(
                "FEC: sent={} recv={} recovered={} dupes={} suppressed={}",
                diag.fec_frames_sent,
                diag.fec_frames_received,
                diag.fec_recoveries,
                diag.duplicate_packets_sent,
                diag.suppressed_duplicates
            ));
            lines.push(format!(
                "Diagnostics file: {}",
                config.diagnostics_path.display()
            ));
            lines.push(format!(
                "Lifecycle file: {}",
                config.lifecycle_path.display()
            ));
            lines.push(format!("Runtime log: {}", config.log_path.display()));
        }
    }

    lines.join("\n")
}

pub fn export_diagnostics(config: &DesktopAppConfig, out_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create export directory {}", out_dir.display()))?;

    let status = status(config)?;
    write_json(
        out_dir.join("desktop-config.public.json"),
        &config.sanitized(),
    )?;
    write_json(out_dir.join("status.snapshot.json"), &status)?;

    copy_if_exists(&config.lifecycle_path, &out_dir.join("lifecycle.json"))?;
    copy_if_exists(&config.diagnostics_path, &out_dir.join("diagnostics.json"))?;
    copy_if_exists(&config.log_path, &out_dir.join("runtime.log"))?;

    let mut report = String::new();
    report.push_str("# Omega Desktop Support Report\n\n");
    report.push_str(&render_status(&status, config, true));
    report.push_str("\n\n## Launcher config\n");
    report.push_str(&format!("- Profile: {}\n", profile_label(config.profile)));
    report.push_str(&format!("- Server: {}\n", config.server_endpoint));
    report.push_str(&format!("- Background mode: {}\n", config.background_mode));
    report.push_str(&format!("- Release channel: {}\n", config.release_channel));
    report.push_str("\n## Runtime log tail\n\n```text\n");
    report.push_str(&tail_log(&config.log_path, 80)?);
    report.push_str("\n```\n");
    std::fs::write(out_dir.join("support-report.md"), report)
        .with_context(|| format!("failed to write support report into {}", out_dir.display()))?;

    Ok(out_dir.to_path_buf())
}

async fn wait_for_runtime_ready(
    config: &DesktopAppConfig,
    timeout: Duration,
) -> anyhow::Result<DesktopStatus> {
    let started = SystemTime::now();
    loop {
        let current = status(config)?;
        if let Some(lifecycle) = &current.lifecycle {
            match lifecycle.state {
                ClientLifecycleState::Connected | ClientLifecycleState::Degraded => {
                    return Ok(current)
                }
                ClientLifecycleState::Failed => {
                    anyhow::bail!(
                        "{}{}",
                        lifecycle.message,
                        lifecycle
                            .suggested_action
                            .as_ref()
                            .map(|action| format!(". Suggested action: {action}"))
                            .unwrap_or_default()
                    );
                }
                ClientLifecycleState::Stopped if !current.runtime_running => {
                    anyhow::bail!("background runtime stopped before reaching connected state");
                }
                _ => {}
            }
        }

        if SystemTime::now()
            .duration_since(started)
            .unwrap_or_default()
            >= timeout
        {
            return Ok(current);
        }

        sleep(Duration::from_millis(400)).await;
    }
}

fn human_state(status: &DesktopStatus) -> &'static str {
    match status.lifecycle.as_ref().map(|snapshot| snapshot.state) {
        Some(ClientLifecycleState::Connected) if status.runtime_running => "Connected",
        Some(ClientLifecycleState::Degraded) if status.runtime_running => "Connected (degraded)",
        Some(ClientLifecycleState::Handshaking) if status.runtime_running => "Connecting",
        Some(ClientLifecycleState::Starting) if status.runtime_running => "Starting",
        Some(ClientLifecycleState::Closing) => "Stopping",
        Some(ClientLifecycleState::Failed) => "Failed",
        Some(ClientLifecycleState::Stopped) => "Stopped",
        _ if status.runtime_running => "Running",
        _ => "Stopped",
    }
}

fn read_pid(path: &Path) -> anyhow::Result<Option<u32>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => Ok(raw.trim().parse::<u32>().ok()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to read pid file {}", path.display())),
    }
}

fn write_pid(path: &Path, pid: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid directory {}", parent.display()))?;
    }
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("failed to write pid file {}", path.display()))?;
    Ok(())
}

fn clear_pid(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to clear pid file {}", path.display())),
    }
}

#[cfg(target_os = "windows")]
fn is_process_running(pid: u32) -> bool {
    let output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($p) {{ $p.Id }}",
                pid
            ),
        ])
        .output();

    match output {
        Ok(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn is_process_running(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn force_kill(pid: u32) -> anyhow::Result<()> {
    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .context("failed to invoke taskkill")?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn force_kill(pid: u32) -> anyhow::Result<()> {
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .context("failed to invoke kill")?;
    Ok(())
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn copy_if_exists(src: &Path, dst: &Path) -> anyhow::Result<()> {
    match std::fs::copy(src, dst) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to copy {} -> {}", src.display(), dst.display())),
    }
}

fn tail_log(path: &Path, max_lines: usize) -> anyhow::Result<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok("runtime log is not available yet".to_string())
        }
        Err(err) => {
            return Err(err)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("failed to open runtime log {}", path.display()))
        }
    };

    let reader = BufReader::new(file);
    let mut lines = reader.lines().collect::<Result<Vec<_>, _>>()?;
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }
    Ok(lines.join("\n"))
}
