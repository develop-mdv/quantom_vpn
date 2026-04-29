use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    Stop,
}

#[derive(Debug, Deserialize)]
struct ControlRequest {
    command: String,
}

pub fn read_control_command(path: impl AsRef<Path>) -> anyhow::Result<Option<ControlCommand>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)?;
    let request: ControlRequest = match serde_json::from_str(&raw) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "ignoring invalid omega control file");
            return Ok(None);
        }
    };

    Ok(match request.command.trim().to_ascii_lowercase().as_str() {
        "stop" | "shutdown" | "disconnect" => Some(ControlCommand::Stop),
        _ => None,
    })
}

pub async fn wait_for_stop(path: PathBuf, poll_interval: Duration) -> anyhow::Result<()> {
    loop {
        if matches!(read_control_command(&path)?, Some(ControlCommand::Stop)) {
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(());
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_command_from_control_file() {
        let path = std::env::temp_dir().join(format!(
            "omega-control-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::write(&path, r#"{"command":"stop","created_at_ms":1}"#).unwrap();

        let command = read_control_command(&path).unwrap();

        assert!(matches!(command, Some(ControlCommand::Stop)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ignores_unknown_control_command() {
        let path = std::env::temp_dir().join(format!(
            "omega-control-unknown-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::write(&path, r#"{"command":"restart"}"#).unwrap();

        let command = read_control_command(&path).unwrap();

        assert!(command.is_none());
        let _ = std::fs::remove_file(path);
    }
}
