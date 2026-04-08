use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

const DEFAULT_HANDSHAKE_MAX_ATTEMPTS_PER_WINDOW: u32 = 48;
const DEFAULT_HANDSHAKE_RATE_WINDOW_SECS: u64 = 10;
const DEFAULT_HANDSHAKE_BLOCK_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct HandshakeAbuseConfig {
    pub max_attempts_per_window: u32,
    pub window: Duration,
    pub block_for: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseVerdict {
    Allowed,
    RateLimited { retry_after_ms: u64 },
}

#[derive(Debug)]
pub struct HandshakeAbuseGuard {
    config: HandshakeAbuseConfig,
    entries: DashMap<IpAddr, AbuseEntry>,
}

#[derive(Debug, Clone)]
struct AbuseEntry {
    window_started: Instant,
    attempts: u32,
    blocked_until: Option<Instant>,
}

impl HandshakeAbuseConfig {
    pub fn from_env() -> Self {
        Self {
            max_attempts_per_window: env_u32(
                "OMEGA_HANDSHAKE_MAX_ATTEMPTS_PER_WINDOW",
                DEFAULT_HANDSHAKE_MAX_ATTEMPTS_PER_WINDOW,
            )
            .max(4),
            window: Duration::from_secs(
                env_u64(
                    "OMEGA_HANDSHAKE_RATE_WINDOW_SECS",
                    DEFAULT_HANDSHAKE_RATE_WINDOW_SECS,
                )
                .max(1),
            ),
            block_for: Duration::from_secs(
                env_u64("OMEGA_HANDSHAKE_BLOCK_SECS", DEFAULT_HANDSHAKE_BLOCK_SECS).max(1),
            ),
        }
    }
}

impl HandshakeAbuseGuard {
    pub fn new() -> Self {
        Self::with_config(HandshakeAbuseConfig::from_env())
    }

    pub fn with_config(config: HandshakeAbuseConfig) -> Self {
        Self {
            config,
            entries: DashMap::new(),
        }
    }

    pub fn register_attempt(&self, ip: IpAddr) -> AbuseVerdict {
        self.register_attempt_at(ip, Instant::now())
    }

    pub fn cleanup(&self) {
        self.cleanup_at(Instant::now());
    }

    fn register_attempt_at(&self, ip: IpAddr, now: Instant) -> AbuseVerdict {
        let mut entry = self.entries.entry(ip).or_insert_with(|| AbuseEntry {
            window_started: now,
            attempts: 0,
            blocked_until: None,
        });

        if let Some(blocked_until) = entry.blocked_until {
            if blocked_until > now {
                return AbuseVerdict::RateLimited {
                    retry_after_ms: blocked_until.duration_since(now).as_millis() as u64,
                };
            }
            entry.window_started = now;
            entry.attempts = 0;
            entry.blocked_until = None;
        }

        if now.duration_since(entry.window_started) >= self.config.window {
            entry.window_started = now;
            entry.attempts = 0;
        }

        entry.attempts = entry.attempts.saturating_add(1);
        if entry.attempts > self.config.max_attempts_per_window {
            let blocked_until = now + self.config.block_for;
            entry.blocked_until = Some(blocked_until);
            return AbuseVerdict::RateLimited {
                retry_after_ms: self.config.block_for.as_millis() as u64,
            };
        }

        AbuseVerdict::Allowed
    }

    fn cleanup_at(&self, now: Instant) {
        let retention = self.config.window.max(self.config.block_for);
        let stale = self
            .entries
            .iter()
            .filter_map(|entry| {
                let blocked_expired = entry
                    .blocked_until
                    .map(|deadline| deadline <= now)
                    .unwrap_or(true);
                if blocked_expired && now.duration_since(entry.window_started) > retention {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for ip in stale {
            self.entries.remove(&ip);
        }
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn config() -> HandshakeAbuseConfig {
        HandshakeAbuseConfig {
            max_attempts_per_window: 2,
            window: Duration::from_secs(5),
            block_for: Duration::from_secs(10),
        }
    }

    #[test]
    fn guard_blocks_after_budget_is_exhausted() {
        let guard = HandshakeAbuseGuard::with_config(config());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let now = Instant::now();

        assert_eq!(guard.register_attempt_at(ip, now), AbuseVerdict::Allowed);
        assert_eq!(guard.register_attempt_at(ip, now), AbuseVerdict::Allowed);
        assert!(matches!(
            guard.register_attempt_at(ip, now),
            AbuseVerdict::RateLimited { .. }
        ));
    }

    #[test]
    fn guard_recovers_after_block_expires() {
        let guard = HandshakeAbuseGuard::with_config(config());
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));
        let now = Instant::now();

        let _ = guard.register_attempt_at(ip, now);
        let _ = guard.register_attempt_at(ip, now);
        assert!(matches!(
            guard.register_attempt_at(ip, now),
            AbuseVerdict::RateLimited { .. }
        ));

        let later = now + Duration::from_secs(11);
        assert_eq!(guard.register_attempt_at(ip, later), AbuseVerdict::Allowed);
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let guard = HandshakeAbuseGuard::with_config(config());
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
        let now = Instant::now();

        let _ = guard.register_attempt_at(ip, now);
        guard.cleanup_at(now + Duration::from_secs(20));

        assert!(guard.entries.is_empty());
    }
}
