use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct RealityKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    version: u32,
    private_key: String,
    public_key: String,
}

const STORED_KEY_VERSION: u32 = 1;

impl RealityKeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn public_base64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }

    pub fn private_base64(&self) -> String {
        B64.encode(self.secret.to_bytes())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read reality key file {}", path.display()))?;
        let stored: StoredKey = serde_json::from_str(&raw)
            .with_context(|| format!("parse reality key file {}", path.display()))?;
        if stored.version != STORED_KEY_VERSION {
            return Err(anyhow!(
                "unsupported reality key version: {} (expected {})",
                stored.version,
                STORED_KEY_VERSION
            ));
        }
        let secret_bytes = B64
            .decode(stored.private_key.as_bytes())
            .context("decode reality private_key (base64)")?;
        let secret_bytes: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| anyhow!("reality private_key must decode to 32 bytes"))?;
        let pair = Self::from_secret_bytes(secret_bytes);

        let stored_pub = B64
            .decode(stored.public_key.as_bytes())
            .context("decode reality public_key (base64)")?;
        if stored_pub.as_slice() != pair.public.as_bytes() {
            return Err(anyhow!(
                "reality key file is corrupted: stored public key does not match private"
            ));
        }
        Ok(pair)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create directory {}", parent.display()))?;
            }
        }
        let stored = StoredKey {
            version: STORED_KEY_VERSION,
            private_key: self.private_base64(),
            public_key: self.public_base64(),
        };
        let json = serde_json::to_string_pretty(&stored)
            .context("serialize reality key file")?;
        write_atomic(path, json.as_bytes())
            .with_context(|| format!("write reality key file {}", path.display()))?;
        Ok(())
    }

    pub fn load_or_generate(path: &Path) -> anyhow::Result<(Self, bool)> {
        if path.exists() {
            return Self::load(path).map(|pair| (pair, false));
        }
        let pair = Self::generate();
        pair.save(path)?;
        Ok((pair, true))
    }
}

fn write_atomic(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp_path: PathBuf = match target.file_name() {
        Some(name) => {
            let mut tmp_name = name.to_os_string();
            tmp_name.push(".tmp");
            target.with_file_name(tmp_name)
        }
        None => target.with_extension("tmp"),
    };
    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reality_x25519.key");
        let original = RealityKeyPair::generate();
        original.save(&path).unwrap();
        let loaded = RealityKeyPair::load(&path).unwrap();
        assert_eq!(original.public.as_bytes(), loaded.public.as_bytes());
        assert_eq!(original.secret.to_bytes(), loaded.secret.to_bytes());
    }

    #[test]
    fn load_or_generate_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("reality_x25519.key");
        let (pair, created) = RealityKeyPair::load_or_generate(&path).unwrap();
        assert!(created);
        assert!(path.exists());
        let (pair2, created2) = RealityKeyPair::load_or_generate(&path).unwrap();
        assert!(!created2);
        assert_eq!(pair.public.as_bytes(), pair2.public.as_bytes());
    }
}
