mod app_config;
mod launcher;
mod update;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;
use app_config::{default_app_config_path, profile_label, DesktopAppConfig};
use launcher::{connect, disconnect, export_diagnostics, reconnect, render_status, status};
use omega_client_runtime::ConnectionProfile;
use update::{apply_staged_bundle, stage_verified_bundle, verify_bundle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("__runtime")) {
        return omega_client_runtime::run_from_env().await;
    }

    let config_path = default_app_config_path();
    let mut config = DesktopAppConfig::load_or_default(&config_path)?;

    match args.first().map(String::as_str) {
        None | Some("status") => {
            let advanced = has_flag(&args, "--advanced");
            let as_json = has_flag(&args, "--json");
            let current = status(&config)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&current)?);
            } else {
                println!("{}", render_status(&current, &config, advanced));
            }
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
        }
        Some("setup") | Some("configure") => {
            apply_setup(&mut config, &args[1..])?;
            config.save(&config_path)?;
            println!(
                "Desktop config saved to {}. Active profile: {}.",
                config_path.display(),
                profile_label(config.profile)
            );
        }
        Some("connect") => {
            let current = connect(&config).await?;
            println!("{}", render_status(&current, &config, false));
        }
        Some("disconnect") => {
            let current = disconnect(&config).await?;
            println!("{}", render_status(&current, &config, false));
        }
        Some("reconnect") => {
            let current = reconnect(&config).await?;
            println!("{}", render_status(&current, &config, false));
        }
        Some("profile") => {
            handle_profile(&mut config, &config_path, &args[1..])?;
        }
        Some("show-config") => {
            println!("{}", serde_json::to_string_pretty(&config.sanitized())?);
        }
        Some("export-diagnostics") => {
            let out_dir = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(default_export_dir);
            let exported = export_diagnostics(&config, &out_dir)?;
            println!("Diagnostics exported to {}", exported.display());
        }
        Some("update") => {
            handle_update(&config, &args[1..])?;
        }
        Some(other) => {
            anyhow::bail!("unknown command `{other}`; run `omega-client-app help`");
        }
    }

    Ok(())
}

fn apply_setup(config: &mut DesktopAppConfig, args: &[String]) -> anyhow::Result<()> {
    config.server_endpoint = resolve_field(
        flag_value(args, "--server"),
        &config.server_endpoint,
        "VPN server endpoint",
        true,
    )?;
    config.device_id = resolve_field(
        flag_value(args, "--device-id"),
        &config.device_id,
        "Device ID",
        true,
    )?;
    config.device_token = resolve_field(
        flag_value(args, "--device-token"),
        &config.device_token,
        "Device token",
        true,
    )?;
    config.device_name = resolve_field(
        flag_value(args, "--device-name"),
        &config.device_name,
        "Device name",
        true,
    )?;
    if let Some(profile) = flag_value(args, "--profile") {
        config.profile = parse_profile(&profile)?;
    }
    if has_flag(args, "--no-background") {
        config.background_mode = false;
    }
    if has_flag(args, "--background") {
        config.background_mode = true;
    }
    if let Some(channel) = flag_value(args, "--channel") {
        config.release_channel = channel;
    }
    if let Some(target) = flag_value(args, "--install-target") {
        config.install_target_path = Some(PathBuf::from(target));
    }
    Ok(())
}

fn handle_profile(
    config: &mut DesktopAppConfig,
    config_path: &Path,
    args: &[String],
) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        None | Some("show") => {
            println!("{}", profile_label(config.profile));
        }
        Some("list") => {
            println!("Gaming");
            println!("General Internet");
            println!("Restricted Fallback");
        }
        Some("set") => {
            let value = args
                .get(1)
                .context("profile set requires one of: gaming, general, restricted")?;
            config.profile = parse_profile(value)?;
            config.save(config_path)?;
            println!("Profile saved: {}", profile_label(config.profile));
        }
        Some(other) => {
            anyhow::bail!("unknown profile command `{other}`");
        }
    }
    Ok(())
}

fn handle_update(config: &DesktopAppConfig, args: &[String]) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("verify") => {
            let (root, manifest, bundle) = parse_verify_triplet(args)?;
            let target_id = flag_value(args, "--target-id");
            let verified = verify_bundle(
                &root,
                &manifest,
                &bundle,
                &config.release_channel,
                target_id.as_deref(),
            )?;
            println!(
                "Verified {} {} for channel {}.",
                verified.target.target_id, verified.target.version, verified.channel
            );
        }
        Some("stage") => {
            let (root, manifest, bundle) = parse_verify_triplet(args)?;
            let target_id = flag_value(args, "--target-id");
            let verified = verify_bundle(
                &root,
                &manifest,
                &bundle,
                &config.release_channel,
                target_id.as_deref(),
            )?;
            let stage_dir = stage_verified_bundle(config, &verified)?;
            println!("Verified update staged in {}", stage_dir.display());
        }
        Some("apply") => {
            let stage_dir = args
                .get(1)
                .map(PathBuf::from)
                .context("update apply requires the staged directory path")?;
            let target_override = flag_value(args, "--target").map(PathBuf::from);
            let applied = apply_staged_bundle(config, &stage_dir, target_override.as_deref())?;
            println!(
                "Applied verified update {} to {}",
                applied.receipt.version,
                applied.target_path.display()
            );
            if let Some(backup) = applied.backup_path {
                println!("Backup saved to {}", backup.display());
            }
        }
        _ => {
            println!("update verify <root.json> <manifest.json> <bundle> [--target-id id]");
            println!("update stage <root.json> <manifest.json> <bundle> [--target-id id]");
            println!("update apply <staged-dir> [--target path]");
        }
    }
    Ok(())
}

fn parse_verify_triplet(args: &[String]) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let root = args
        .get(1)
        .map(PathBuf::from)
        .context("missing trusted root path")?;
    let manifest = args
        .get(2)
        .map(PathBuf::from)
        .context("missing manifest path")?;
    let bundle = args
        .get(3)
        .map(PathBuf::from)
        .context("missing bundle path")?;
    Ok((root, manifest, bundle))
}

fn resolve_field(
    cli_value: Option<String>,
    current_value: &str,
    label: &str,
    required: bool,
) -> anyhow::Result<String> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    if !current_value.trim().is_empty() {
        return Ok(current_value.to_string());
    }
    if !required {
        return Ok(String::new());
    }
    prompt(label)
}

fn prompt(label: &str) -> anyhow::Result<String> {
    print!("{label}: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let value = buf.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    Ok(value)
}

fn parse_profile(value: &str) -> anyhow::Result<ConnectionProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "gaming" => Ok(ConnectionProfile::Gaming),
        "general" | "internet" | "default" | "general_internet" => {
            Ok(ConnectionProfile::GeneralInternet)
        }
        "restricted" | "fallback" | "restricted_fallback" => {
            Ok(ConnectionProfile::RestrictedFallback)
        }
        _ => anyhow::bail!("unknown profile `{value}`; use gaming, general, or restricted"),
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn default_export_dir() -> PathBuf {
    PathBuf::from(format!("omega-client/state/exports/{}", now_ms()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn print_help() {
    println!("omega-client-app status [--advanced] [--json]");
    println!("omega-client-app setup [--server host:port --device-id uuid --device-token token --device-name name --profile gaming|general|restricted]");
    println!("omega-client-app connect");
    println!("omega-client-app disconnect");
    println!("omega-client-app reconnect");
    println!("omega-client-app profile show|list|set <value>");
    println!("omega-client-app show-config");
    println!("omega-client-app export-diagnostics [out-dir]");
    println!("omega-client-app update verify|stage|apply ...");
}
