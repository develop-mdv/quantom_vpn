use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;
use ring::signature::{self};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app_config::DesktopAppConfig;

const MAX_ROOT_BYTES: u64 = 128 * 1024;
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_ROOT_KEYS: usize = 32;
const MAX_SIGNATURES_PER_MANIFEST: usize = 32;
const MAX_TARGETS_PER_MANIFEST: usize = 128;
const MAX_RELEASE_TARGET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_NAME_LEN: usize = 128;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const SHA256_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedReleaseRoot {
    pub version: u32,
    pub threshold: usize,
    pub keys: Vec<TrustedReleaseKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedReleaseKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReleaseManifest {
    pub signed: ReleaseTargetsMetadata,
    pub signatures: Vec<ReleaseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseTargetsMetadata {
    pub version: u32,
    pub channel: String,
    pub expires_at_ms: u64,
    pub min_root_version: u32,
    pub targets: Vec<ReleaseTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseTarget {
    pub target_id: String,
    pub file_name: String,
    pub version: String,
    pub platform: String,
    pub length: u64,
    pub sha256_hex: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseSignature {
    pub key_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedBundle {
    pub root_path: PathBuf,
    pub manifest_path: PathBuf,
    pub bundle_path: PathBuf,
    pub channel: String,
    pub target: ReleaseTarget,
    pub manifest_version: u32,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedUpdateReceipt {
    pub target_id: String,
    pub version: String,
    pub channel: String,
    pub file_name: String,
    pub staged_bundle_path: PathBuf,
    pub manifest_path: PathBuf,
    pub root_path: PathBuf,
    pub manifest_version: u32,
    pub sha256_hex: String,
    pub length: u64,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedUpdate {
    pub target_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub applied_at_ms: u64,
    pub receipt: StagedUpdateReceipt,
}

pub fn verify_bundle(
    root_path: &Path,
    manifest_path: &Path,
    bundle_path: &Path,
    required_channel: &str,
    target_id: Option<&str>,
) -> anyhow::Result<VerifiedBundle> {
    let root = load_root(root_path)?;
    let manifest = load_manifest(manifest_path)?;

    validate_root(&root)?;
    validate_manifest(&manifest)?;
    if manifest.signed.min_root_version > root.version {
        anyhow::bail!(
            "manifest requires root version {} but trusted root is {}",
            manifest.signed.min_root_version,
            root.version
        );
    }
    if manifest.signed.channel != required_channel {
        anyhow::bail!(
            "manifest channel {} does not match requested channel {}",
            manifest.signed.channel,
            required_channel
        );
    }
    if manifest.signed.expires_at_ms <= now_ms() {
        anyhow::bail!("release manifest has expired and cannot be trusted anymore");
    }

    verify_manifest_signatures(&root, &manifest)?;
    let file_name_hint = bundle_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let target = select_target(&manifest.signed.targets, target_id, file_name_hint)?;
    validate_target(target)?;

    let bundle_meta = std::fs::metadata(bundle_path)
        .with_context(|| format!("failed to stat bundle {}", bundle_path.display()))?;
    let bundle_len = bundle_meta.len();
    if bundle_len > MAX_RELEASE_TARGET_BYTES {
        anyhow::bail!(
            "bundle {} exceeds maximum allowed size of {} bytes",
            bundle_path.display(),
            MAX_RELEASE_TARGET_BYTES
        );
    }
    if target.length != bundle_len {
        anyhow::bail!(
            "bundle length mismatch: expected {} bytes but got {} bytes",
            target.length,
            bundle_len
        );
    }

    let bundle_bytes = read_limited(bundle_path, MAX_RELEASE_TARGET_BYTES, "bundle")?;
    let bundle_sha = hex_encode(&Sha256::digest(&bundle_bytes));
    if !target.sha256_hex.eq_ignore_ascii_case(&bundle_sha) {
        anyhow::bail!(
            "bundle digest mismatch: expected {} but got {}",
            target.sha256_hex,
            bundle_sha
        );
    }

    Ok(VerifiedBundle {
        root_path: root_path.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        bundle_path: bundle_path.to_path_buf(),
        channel: required_channel.to_string(),
        target: target.clone(),
        manifest_version: manifest.signed.version,
        verified_at_ms: now_ms(),
    })
}

pub fn stage_verified_bundle(
    config: &DesktopAppConfig,
    verified: &VerifiedBundle,
) -> anyhow::Result<PathBuf> {
    let safe_file_name = safe_file_name_component(&verified.target.file_name)?;
    let stage_dir = config.update_root_path.join("staged").join(format!(
        "{}-{}",
        verified.target.target_id, verified.target.version
    ));
    std::fs::create_dir_all(&stage_dir)
        .with_context(|| format!("failed to create staged update dir {}", stage_dir.display()))?;

    let staged_bundle = stage_dir.join(&safe_file_name);
    if staged_bundle.parent() != Some(stage_dir.as_path()) {
        anyhow::bail!("staged bundle escaped the stage directory");
    }
    std::fs::copy(&verified.bundle_path, &staged_bundle).with_context(|| {
        format!(
            "failed to stage verified bundle {} -> {}",
            verified.bundle_path.display(),
            staged_bundle.display()
        )
    })?;

    let receipt = StagedUpdateReceipt {
        target_id: verified.target.target_id.clone(),
        version: verified.target.version.clone(),
        channel: verified.channel.clone(),
        file_name: safe_file_name,
        staged_bundle_path: staged_bundle,
        manifest_path: verified.manifest_path.clone(),
        root_path: verified.root_path.clone(),
        manifest_version: verified.manifest_version,
        sha256_hex: verified.target.sha256_hex.clone(),
        length: verified.target.length,
        verified_at_ms: verified.verified_at_ms,
    };
    write_json(stage_dir.join("receipt.json"), &receipt)?;
    Ok(stage_dir)
}
pub fn apply_staged_bundle(
    config: &DesktopAppConfig,
    staged_dir: &Path,
    target_override: Option<&Path>,
) -> anyhow::Result<AppliedUpdate> {
    let receipt = load_receipt(staged_dir)?;
    if receipt.length == 0 || receipt.length > MAX_RELEASE_TARGET_BYTES {
        anyhow::bail!("staged bundle length is outside the trusted budget");
    }
    let safe_file_name = safe_file_name_component(&receipt.file_name)?;
    let staged_name = receipt
        .staged_bundle_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("staged bundle path is missing a file name"))?;
    if staged_name != safe_file_name {
        anyhow::bail!("staged bundle receipt does not match the staged file path");
    }

    let bundle = read_limited(
        &receipt.staged_bundle_path,
        MAX_RELEASE_TARGET_BYTES,
        "staged bundle",
    )?;
    let digest = hex_encode(&Sha256::digest(&bundle));
    if !receipt.sha256_hex.eq_ignore_ascii_case(&digest) {
        anyhow::bail!("staged bundle digest changed after verification");
    }
    if receipt.length != bundle.len() as u64 {
        anyhow::bail!("staged bundle length changed after verification");
    }

    let target_path = match target_override {
        Some(path) => path.to_path_buf(),
        None => config
            .install_target_path
            .clone()
            .unwrap_or(std::env::current_exe().context("failed to resolve current executable")?),
    };
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create install target directory {}",
                parent.display()
            )
        })?;
    }

    let backup_path = if target_path.exists() {
        let backup_dir = config.update_root_path.join("backup");
        std::fs::create_dir_all(&backup_dir).with_context(|| {
            format!("failed to create backup directory {}", backup_dir.display())
        })?;
        let backup_path = backup_dir.join(format!(
            "{}-{}.bak",
            target_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("omega-client-app"),
            now_ms()
        ));
        std::fs::copy(&target_path, &backup_path).with_context(|| {
            format!(
                "failed to create backup {} -> {}",
                target_path.display(),
                backup_path.display()
            )
        })?;
        Some(backup_path)
    } else {
        None
    };

    std::fs::write(&target_path, &bundle).with_context(|| {
        format!(
            "failed to write verified update into {}",
            target_path.display()
        )
    })?;

    let applied = AppliedUpdate {
        target_path: target_path.clone(),
        backup_path,
        applied_at_ms: now_ms(),
        receipt,
    };
    write_json(staged_dir.join("applied.json"), &applied)?;
    Ok(applied)
}

fn load_root(path: &Path) -> anyhow::Result<TrustedReleaseRoot> {
    load_json_limited(path, MAX_ROOT_BYTES, "trusted root")
}

fn load_manifest(path: &Path) -> anyhow::Result<SignedReleaseManifest> {
    load_json_limited(path, MAX_MANIFEST_BYTES, "release manifest")
}

fn load_receipt(stage_dir: &Path) -> anyhow::Result<StagedUpdateReceipt> {
    load_json_limited(
        &stage_dir.join("receipt.json"),
        MAX_RECEIPT_BYTES,
        "staged receipt",
    )
}

fn verify_manifest_signatures(
    root: &TrustedReleaseRoot,
    manifest: &SignedReleaseManifest,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(&manifest.signed)?;
    let mut valid_signers = BTreeSet::new();

    for signature in &manifest.signatures {
        let Some(key) = root.keys.iter().find(|key| key.key_id == signature.key_id) else {
            continue;
        };

        let public_key = hex_decode_fixed(
            &key.public_key_hex,
            ED25519_PUBLIC_KEY_LEN,
            "trusted root public key",
        )?;
        let signature_bytes = hex_decode_fixed(
            &signature.signature_hex,
            ED25519_SIGNATURE_LEN,
            "manifest signature",
        )?;
        let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
        if verifier.verify(&payload, &signature_bytes).is_ok() {
            valid_signers.insert(key.key_id.clone());
        }
    }

    if valid_signers.len() < root.threshold {
        anyhow::bail!(
            "release manifest has only {} valid signatures but {} are required",
            valid_signers.len(),
            root.threshold
        );
    }

    Ok(())
}

fn select_target<'a>(
    targets: &'a [ReleaseTarget],
    target_id: Option<&str>,
    file_name_hint: &str,
) -> anyhow::Result<&'a ReleaseTarget> {
    if let Some(target_id) = target_id {
        return targets
            .iter()
            .find(|target| target.target_id == target_id)
            .ok_or_else(|| anyhow::anyhow!("target {target_id} is not present in the manifest"));
    }

    if let Some(target) = targets
        .iter()
        .find(|target| target.file_name == file_name_hint)
    {
        return Ok(target);
    }

    if targets.len() == 1 {
        return Ok(&targets[0]);
    }

    anyhow::bail!("manifest contains multiple targets; specify the target id explicitly")
}

fn load_json_limited<T>(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let raw = read_limited(path, max_bytes, label)?;
    serde_json::from_slice(&raw)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("failed to parse {} {}", label, path.display()))
}

fn read_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {} {}", label, path.display()))?;
    if metadata.len() > max_bytes {
        anyhow::bail!(
            "{} {} exceeds maximum allowed size of {} bytes",
            label,
            path.display(),
            max_bytes
        );
    }
    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read {} {}", label, path.display()))?;
    if raw.len() as u64 > max_bytes {
        anyhow::bail!(
            "{} {} exceeds maximum allowed size of {} bytes after read",
            label,
            path.display(),
            max_bytes
        );
    }
    Ok(raw)
}
fn validate_root(root: &TrustedReleaseRoot) -> anyhow::Result<()> {
    if root.version == 0 {
        anyhow::bail!("trusted root version must be at least 1");
    }
    if root.threshold == 0 {
        anyhow::bail!("trusted root threshold must be at least 1");
    }
    if root.keys.is_empty() {
        anyhow::bail!("trusted root must contain at least one signing key");
    }
    if root.keys.len() > MAX_ROOT_KEYS {
        anyhow::bail!(
            "trusted root contains {} keys but the maximum supported set is {}",
            root.keys.len(),
            MAX_ROOT_KEYS
        );
    }
    if root.threshold > root.keys.len() {
        anyhow::bail!(
            "trusted root threshold {} exceeds key count {}",
            root.threshold,
            root.keys.len()
        );
    }

    let mut key_ids = BTreeSet::new();
    for key in &root.keys {
        if key.key_id.trim().is_empty() {
            anyhow::bail!("trusted root contains an empty key id");
        }
        if !key_ids.insert(key.key_id.clone()) {
            anyhow::bail!("trusted root contains duplicate key id {}", key.key_id);
        }
        if !key.algorithm.eq_ignore_ascii_case("ed25519") {
            anyhow::bail!(
                "trusted root key {} uses unsupported algorithm {}",
                key.key_id,
                key.algorithm
            );
        }
        hex_decode_fixed(
            &key.public_key_hex,
            ED25519_PUBLIC_KEY_LEN,
            "trusted root public key",
        )?;
    }

    Ok(())
}

fn validate_manifest(manifest: &SignedReleaseManifest) -> anyhow::Result<()> {
    if manifest.signed.version == 0 {
        anyhow::bail!("release manifest version must be at least 1");
    }
    if manifest.signed.channel.trim().is_empty() {
        anyhow::bail!("release manifest channel must not be empty");
    }
    if manifest.signed.expires_at_ms == 0 {
        anyhow::bail!("release manifest expiration must be set");
    }
    if manifest.signatures.is_empty() {
        anyhow::bail!("release manifest must contain at least one signature");
    }
    if manifest.signatures.len() > MAX_SIGNATURES_PER_MANIFEST {
        anyhow::bail!(
            "release manifest contains {} signatures but the maximum supported set is {}",
            manifest.signatures.len(),
            MAX_SIGNATURES_PER_MANIFEST
        );
    }
    if manifest.signed.targets.is_empty() {
        anyhow::bail!("release manifest must contain at least one target");
    }
    if manifest.signed.targets.len() > MAX_TARGETS_PER_MANIFEST {
        anyhow::bail!(
            "release manifest contains {} targets but the maximum supported set is {}",
            manifest.signed.targets.len(),
            MAX_TARGETS_PER_MANIFEST
        );
    }

    let mut signature_key_ids = BTreeSet::new();
    for signature in &manifest.signatures {
        if signature.key_id.trim().is_empty() {
            anyhow::bail!("release manifest contains a signature without a key id");
        }
        if !signature_key_ids.insert(signature.key_id.clone()) {
            anyhow::bail!(
                "release manifest contains duplicate signatures for key {}",
                signature.key_id
            );
        }
        hex_decode_fixed(
            &signature.signature_hex,
            ED25519_SIGNATURE_LEN,
            "manifest signature",
        )?;
    }

    let mut target_ids = BTreeSet::new();
    let mut file_names = BTreeSet::new();
    for target in &manifest.signed.targets {
        validate_target(target)?;
        if !target_ids.insert(target.target_id.clone()) {
            anyhow::bail!(
                "release manifest contains duplicate target id {}",
                target.target_id
            );
        }
        if !file_names.insert(target.file_name.clone()) {
            anyhow::bail!(
                "release manifest contains duplicate file name {}",
                target.file_name
            );
        }
    }

    Ok(())
}

fn validate_target(target: &ReleaseTarget) -> anyhow::Result<()> {
    if target.target_id.trim().is_empty() {
        anyhow::bail!("release target id must not be empty");
    }
    if target.version.trim().is_empty() {
        anyhow::bail!("release target version must not be empty");
    }
    if target.platform.trim().is_empty() {
        anyhow::bail!("release target platform must not be empty");
    }
    safe_file_name_component(&target.file_name)?;
    if target.length == 0 {
        anyhow::bail!("release target {} has zero length", target.target_id);
    }
    if target.length > MAX_RELEASE_TARGET_BYTES {
        anyhow::bail!(
            "release target {} exceeds the maximum allowed bundle size of {} bytes",
            target.target_id,
            MAX_RELEASE_TARGET_BYTES
        );
    }
    hex_decode_fixed(
        &target.sha256_hex,
        SHA256_DIGEST_LEN,
        "release target sha256",
    )?;
    Ok(())
}

fn safe_file_name_component(file_name: &str) -> anyhow::Result<String> {
    let trimmed = file_name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("unsafe release file name: empty names are not allowed");
    }
    if trimmed.len() > MAX_FILE_NAME_LEN {
        anyhow::bail!(
            "unsafe release file name: {} exceeds {} characters",
            trimmed,
            MAX_FILE_NAME_LEN
        );
    }
    if trimmed == "." || trimmed == ".." {
        anyhow::bail!("unsafe release file name: traversal components are not allowed");
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains(':') {
        anyhow::bail!("unsafe release file name: path separators are not allowed");
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        anyhow::bail!(
            "unsafe release file name: only ASCII letters, digits, '.', '-' and '_' are allowed"
        );
    }
    let path = Path::new(trimmed);
    if path.file_name().and_then(|name| name.to_str()) != Some(trimmed)
        || path.components().count() != 1
    {
        anyhow::bail!("unsafe release file name: expected a single path component");
    }
    Ok(trimmed.to_string())
}

fn hex_decode_fixed(value: &str, expected_len: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    let decoded = hex_decode(value)?;
    if decoded.len() != expected_len {
        anyhow::bail!(
            "{} must decode to {} bytes, but decoded to {} bytes",
            label,
            expected_len,
            decoded.len()
        );
    }
    Ok(decoded)
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length");
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = from_hex(pair[0])?;
        let low = from_hex(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

fn from_hex(ch: u8) -> anyhow::Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => anyhow::bail!("invalid hex digit"),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    #[test]
    fn verify_bundle_accepts_threshold_signatures() {
        let test_dir = temp_test_dir("verify_bundle_accepts_threshold_signatures");
        let bundle_path = test_dir.join("omega-client-app.bin");
        std::fs::write(&bundle_path, b"trusted-update-binary").unwrap();

        let rng = ring::rand::SystemRandom::new();
        let key_a = signature::Ed25519KeyPair::from_pkcs8(
            signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let key_b = signature::Ed25519KeyPair::from_pkcs8(
            signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref(),
        )
        .unwrap();

        let target = ReleaseTarget {
            target_id: "desktop-windows".to_string(),
            file_name: "omega-client-app.bin".to_string(),
            version: "1.2.3".to_string(),
            platform: "windows-x86_64".to_string(),
            length: 21,
            sha256_hex: hex_encode(&Sha256::digest(b"trusted-update-binary")),
            description: "desktop test build".to_string(),
        };
        let signed = ReleaseTargetsMetadata {
            version: 7,
            channel: "stable".to_string(),
            expires_at_ms: now_ms() + 60_000,
            min_root_version: 1,
            targets: vec![target.clone()],
        };
        let payload = serde_json::to_vec(&signed).unwrap();
        let manifest = SignedReleaseManifest {
            signed,
            signatures: vec![
                ReleaseSignature {
                    key_id: "root-a".to_string(),
                    signature_hex: hex_encode(key_a.sign(&payload).as_ref()),
                },
                ReleaseSignature {
                    key_id: "root-b".to_string(),
                    signature_hex: hex_encode(key_b.sign(&payload).as_ref()),
                },
            ],
        };
        let root = TrustedReleaseRoot {
            version: 1,
            threshold: 2,
            keys: vec![
                TrustedReleaseKey {
                    key_id: "root-a".to_string(),
                    algorithm: "ed25519".to_string(),
                    public_key_hex: hex_encode(key_a.public_key().as_ref()),
                },
                TrustedReleaseKey {
                    key_id: "root-b".to_string(),
                    algorithm: "ed25519".to_string(),
                    public_key_hex: hex_encode(key_b.public_key().as_ref()),
                },
            ],
        };

        let root_path = test_dir.join("root.json");
        let manifest_path = test_dir.join("manifest.json");
        write_json(root_path.clone(), &root).unwrap();
        write_json(manifest_path.clone(), &manifest).unwrap();

        let verified = verify_bundle(&root_path, &manifest_path, &bundle_path, "stable", None)
            .expect("bundle should verify");
        assert_eq!(verified.target.target_id, target.target_id);
    }

    #[test]
    fn verify_bundle_rejects_digest_mismatch() {
        let test_dir = temp_test_dir("verify_bundle_rejects_digest_mismatch");
        let bundle_path = test_dir.join("omega-client-app.bin");
        std::fs::write(&bundle_path, b"trusted-update-binary").unwrap();

        let rng = ring::rand::SystemRandom::new();
        let key = signature::Ed25519KeyPair::from_pkcs8(
            signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let signed = ReleaseTargetsMetadata {
            version: 1,
            channel: "stable".to_string(),
            expires_at_ms: now_ms() + 60_000,
            min_root_version: 1,
            targets: vec![ReleaseTarget {
                target_id: "desktop-windows".to_string(),
                file_name: "omega-client-app.bin".to_string(),
                version: "1.2.3".to_string(),
                platform: "windows-x86_64".to_string(),
                length: 21,
                sha256_hex: "00".repeat(32),
                description: "desktop test build".to_string(),
            }],
        };
        let payload = serde_json::to_vec(&signed).unwrap();
        let manifest = SignedReleaseManifest {
            signed,
            signatures: vec![ReleaseSignature {
                key_id: "root".to_string(),
                signature_hex: hex_encode(key.sign(&payload).as_ref()),
            }],
        };
        let root = TrustedReleaseRoot {
            version: 1,
            threshold: 1,
            keys: vec![TrustedReleaseKey {
                key_id: "root".to_string(),
                algorithm: "ed25519".to_string(),
                public_key_hex: hex_encode(key.public_key().as_ref()),
            }],
        };

        let root_path = test_dir.join("root.json");
        let manifest_path = test_dir.join("manifest.json");
        write_json(root_path.clone(), &root).unwrap();
        write_json(manifest_path.clone(), &manifest).unwrap();

        let err = verify_bundle(&root_path, &manifest_path, &bundle_path, "stable", None)
            .expect_err("digest mismatch should fail");
        assert!(err.to_string().contains("digest mismatch"));
    }
    #[test]
    fn verify_bundle_rejects_invalid_root_threshold() {
        let test_dir = temp_test_dir("verify_bundle_rejects_invalid_root_threshold");
        let bundle_path = test_dir.join("omega-client-app.bin");
        std::fs::write(&bundle_path, b"trusted-update-binary").unwrap();

        let rng = ring::rand::SystemRandom::new();
        let key = signature::Ed25519KeyPair::from_pkcs8(
            signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let target = ReleaseTarget {
            target_id: "desktop-windows".to_string(),
            file_name: "omega-client-app.bin".to_string(),
            version: "1.2.3".to_string(),
            platform: "windows-x86_64".to_string(),
            length: 21,
            sha256_hex: hex_encode(&Sha256::digest(b"trusted-update-binary")),
            description: "desktop test build".to_string(),
        };
        let signed = ReleaseTargetsMetadata {
            version: 1,
            channel: "stable".to_string(),
            expires_at_ms: now_ms() + 60_000,
            min_root_version: 1,
            targets: vec![target],
        };
        let payload = serde_json::to_vec(&signed).unwrap();
        let manifest = SignedReleaseManifest {
            signed,
            signatures: vec![ReleaseSignature {
                key_id: "root".to_string(),
                signature_hex: hex_encode(key.sign(&payload).as_ref()),
            }],
        };
        let root = TrustedReleaseRoot {
            version: 1,
            threshold: 2,
            keys: vec![TrustedReleaseKey {
                key_id: "root".to_string(),
                algorithm: "ed25519".to_string(),
                public_key_hex: hex_encode(key.public_key().as_ref()),
            }],
        };

        let root_path = test_dir.join("root.json");
        let manifest_path = test_dir.join("manifest.json");
        write_json(root_path.clone(), &root).unwrap();
        write_json(manifest_path.clone(), &manifest).unwrap();

        let err = verify_bundle(&root_path, &manifest_path, &bundle_path, "stable", None)
            .expect_err("invalid root threshold should fail");
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn verify_bundle_rejects_unsafe_target_file_name() {
        let test_dir = temp_test_dir("verify_bundle_rejects_unsafe_target_file_name");
        let bundle_path = test_dir.join("omega-client-app.bin");
        std::fs::write(&bundle_path, b"trusted-update-binary").unwrap();

        let rng = ring::rand::SystemRandom::new();
        let key = signature::Ed25519KeyPair::from_pkcs8(
            signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let signed = ReleaseTargetsMetadata {
            version: 1,
            channel: "stable".to_string(),
            expires_at_ms: now_ms() + 60_000,
            min_root_version: 1,
            targets: vec![ReleaseTarget {
                target_id: "desktop-windows".to_string(),
                file_name: "../omega-client-app.bin".to_string(),
                version: "1.2.3".to_string(),
                platform: "windows-x86_64".to_string(),
                length: 21,
                sha256_hex: hex_encode(&Sha256::digest(b"trusted-update-binary")),
                description: "desktop test build".to_string(),
            }],
        };
        let payload = serde_json::to_vec(&signed).unwrap();
        let manifest = SignedReleaseManifest {
            signed,
            signatures: vec![ReleaseSignature {
                key_id: "root".to_string(),
                signature_hex: hex_encode(key.sign(&payload).as_ref()),
            }],
        };
        let root = TrustedReleaseRoot {
            version: 1,
            threshold: 1,
            keys: vec![TrustedReleaseKey {
                key_id: "root".to_string(),
                algorithm: "ed25519".to_string(),
                public_key_hex: hex_encode(key.public_key().as_ref()),
            }],
        };

        let root_path = test_dir.join("root.json");
        let manifest_path = test_dir.join("manifest.json");
        write_json(root_path.clone(), &root).unwrap();
        write_json(manifest_path.clone(), &manifest).unwrap();

        let err = verify_bundle(&root_path, &manifest_path, &bundle_path, "stable", None)
            .expect_err("unsafe target file name should fail");
        assert!(err.to_string().contains("unsafe release file name"));
    }

    #[test]
    fn stage_verified_bundle_rejects_escape_file_name() {
        let test_dir = temp_test_dir("stage_verified_bundle_rejects_escape_file_name");
        let bundle_path = test_dir.join("omega-client-app.bin");
        std::fs::write(&bundle_path, b"trusted-update-binary").unwrap();

        let config = DesktopAppConfig {
            update_root_path: test_dir.join("updates"),
            ..DesktopAppConfig::default()
        };
        let verified = VerifiedBundle {
            root_path: test_dir.join("root.json"),
            manifest_path: test_dir.join("manifest.json"),
            bundle_path,
            channel: "stable".to_string(),
            target: ReleaseTarget {
                target_id: "desktop-windows".to_string(),
                file_name: "..\\evil.exe".to_string(),
                version: "1.2.3".to_string(),
                platform: "windows-x86_64".to_string(),
                length: 21,
                sha256_hex: hex_encode(&Sha256::digest(b"trusted-update-binary")),
                description: "desktop test build".to_string(),
            },
            manifest_version: 1,
            verified_at_ms: now_ms(),
        };

        let err = stage_verified_bundle(&config, &verified)
            .expect_err("unsafe staged file name should fail");
        assert!(err.to_string().contains("unsafe release file name"));
    }
    #[test]
    fn hex_roundtrip_covers_all_byte_values() {
        let sample = (0u8..=255).collect::<Vec<_>>();
        let encoded = hex_encode(&sample);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, sample);
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "omega-client-app-tests-{}-{}-{}",
            name,
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
