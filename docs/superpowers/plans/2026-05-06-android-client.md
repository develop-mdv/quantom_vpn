# Android Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Android Kotlin client shell for Omega VPN with native Rust bridge boundaries and per-app split tunneling.

**Architecture:** Kotlin owns Android `VpnService`, foreground lifecycle, UI, settings and installed-app selection. Rust is exposed as an Android `cdylib` through JNI and will become the two-phase Omega runtime bridge: handshake returns TUN params, Kotlin creates the VPN fd, Rust runs datapath on that fd.

**Tech Stack:** Kotlin, Android SDK, programmatic Android views, `VpnService.Builder`, SharedPreferences, Rust `cdylib`, Cargo tests.

---

## File Structure

- `omega-android/settings.gradle.kts`: standalone Android project settings.
- `omega-android/build.gradle.kts`: plugin versions available from local Gradle cache.
- `omega-android/app/build.gradle.kts`: Android app module, Kotlin and native jniLibs source set.
- `omega-android/app/src/main/AndroidManifest.xml`: app, activity, VPN service and permissions.
- `omega-android/app/src/main/java/vpn/myboroda/omega/ProfileStore.kt`: connection profile and split settings persistence.
- `omega-android/app/src/main/java/vpn/myboroda/omega/ConnectionCode.kt`: parser for `omega://connect/...` payloads and manual fields.
- `omega-android/app/src/main/java/vpn/myboroda/omega/AppSplitRepository.kt`: installed-app loading and package filtering.
- `omega-android/app/src/main/java/vpn/myboroda/omega/OmegaNative.kt`: Kotlin JNI wrapper.
- `omega-android/app/src/main/java/vpn/myboroda/omega/OmegaVpnService.kt`: `VpnService` implementation and builder rules.
- `omega-android/app/src/main/java/vpn/myboroda/omega/MainActivity.kt`: programmatic UI.
- `omega-android/app/src/main/res/drawable/*`: deterministic vector assets.
- `omega-android/native/README.md`: native build instructions.
- `omega-android-bridge/Cargo.toml`: Rust Android bridge crate.
- `omega-android-bridge/src/lib.rs`: FFI-safe config validation and JNI entrypoints.
- `omega-android-bridge/src/config.rs`: host-testable parser/validator.
- `Cargo.toml`: workspace membership.
- `.gitignore`: Android build output ignores.

### Task 1: Rust Bridge Config

**Files:**
- Create: `omega-android-bridge/Cargo.toml`
- Create: `omega-android-bridge/src/config.rs`
- Create: `omega-android-bridge/src/lib.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write failing config tests**

Add tests in `omega-android-bridge/src/config.rs` for:

```rust
#[test]
fn parses_required_profile_fields() {
    let config = AndroidProfile::parse(
        "72.56.88.224:51820",
        "550e8400-e29b-41d4-a716-446655440000",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "android",
        "auto",
    )
    .unwrap();

    assert_eq!(config.server, "72.56.88.224:51820");
    assert_eq!(config.platform, "android");
    assert_eq!(config.transport, "auto");
}

#[test]
fn rejects_bad_device_token_length() {
    let err = AndroidProfile::parse(
        "72.56.88.224:51820",
        "550e8400-e29b-41d4-a716-446655440000",
        "abcd",
        "android",
        "auto",
    )
    .unwrap_err();

    assert!(err.contains("device token"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p omega-android-bridge`

Expected: fail because the crate or `AndroidProfile` does not exist.

- [ ] **Step 3: Implement minimal bridge config**

Create a `cdylib` crate with no new external dependencies. Implement
`AndroidProfile::parse` with server non-empty validation, UUID shape validation,
64-hex-char token validation, platform normalization and transport normalization.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p omega-android-bridge`

Expected: config tests pass.

### Task 2: Android Project Skeleton

**Files:**
- Create: `omega-android/settings.gradle.kts`
- Create: `omega-android/build.gradle.kts`
- Create: `omega-android/app/build.gradle.kts`
- Create: `omega-android/app/src/main/AndroidManifest.xml`
- Create: `omega-android/app/src/main/res/values/strings.xml`
- Create: `omega-android/app/src/main/res/values/colors.xml`
- Create: `omega-android/app/src/main/res/drawable/ic_omega_mark.xml`
- Create: `omega-android/app/src/main/res/drawable/ic_vpn_status.xml`
- Create: `omega-android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`
- Create: `omega-android/app/src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml`
- Create: `omega-android/app/src/main/res/drawable/ic_launcher_background.xml`
- Create: `omega-android/app/src/main/res/drawable/ic_launcher_foreground.xml`

- [ ] **Step 1: Add Android project files**

Use `com.android.application` and `org.jetbrains.kotlin.android`, package
`vpn.myboroda.omega`, `minSdk 23`, `targetSdk 35`, Java/Kotlin 17, and native
libs from `src/main/jniLibs`.

- [ ] **Step 2: Add manifest**

Declare `INTERNET`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`, `MainActivity`
and a `VpnService` with `android.permission.BIND_VPN_SERVICE`.

- [ ] **Step 3: Add deterministic assets**

Use vector drawables so the app builds without generated bitmap dependencies.

### Task 3: Kotlin Profile And Split Settings

**Files:**
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/ConnectionCode.kt`
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/ProfileStore.kt`
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/AppSplitRepository.kt`

- [ ] **Step 1: Implement connection parsing**

Support manual fields and `omega://connect/?server=...&device_id=...&token=...`
query parameters. Reject blank server, device id or token.

- [ ] **Step 2: Implement persistence**

Store server, device id, token, device name, transport, split mode and selected
packages in SharedPreferences.

- [ ] **Step 3: Implement installed-app repository**

Load launchable apps from `PackageManager`, sort by label, and always mark the
current app package as non-selectable.

### Task 4: VPN Service

**Files:**
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/OmegaNative.kt`
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/OmegaVpnService.kt`

- [ ] **Step 1: Implement native wrapper**

Load `omega_android_bridge` if present. Expose `validateProfile`, `startHandshake`,
`continueWithTunFd` and `stop`. If the native library is absent, return a clear
error string instead of crashing the app.

- [ ] **Step 2: Implement `VpnService.Builder` setup**

Build routes `0.0.0.0/0`, optional `::/0`, DNS defaults and MTU from native
handshake params. Apply exactly one app rule mode:

```kotlin
when (settings.splitMode) {
    SplitMode.EXCLUDE_SELECTED -> {
        val denied = settings.selectedPackages + packageName
        denied.distinct().forEach(builder::addDisallowedApplication)
    }
    SplitMode.ONLY_SELECTED -> {
        settings.selectedPackages
            .filterNot { it == packageName }
            .distinct()
            .forEach(builder::addAllowedApplication)
    }
}
```

- [ ] **Step 3: Implement foreground lifecycle**

Show a persistent notification while connecting/connected and close the TUN fd
on disconnect.

### Task 5: Main UI

**Files:**
- Create: `omega-android/app/src/main/java/vpn/myboroda/omega/MainActivity.kt`

- [ ] **Step 1: Build first screen**

Programmatic Android views: status header, connection code field, manual
profile fields, connect/disconnect button, transport selector and split mode
selector.

- [ ] **Step 2: Build app list**

Add search, selectable rows and current package disabled state. Persist package
selection immediately.

- [ ] **Step 3: Wire VPN permission flow**

Use `VpnService.prepare`, start service on consent, and show errors returned by
the service/native wrapper.

### Task 6: Native Build Notes And Verification

**Files:**
- Create: `omega-android/native/README.md`
- Modify: `.gitignore`

- [ ] **Step 1: Document native build**

Document Rust targets:

```powershell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Document copying `.so` files into `omega-android/app/src/main/jniLibs/<abi>/`.

- [ ] **Step 2: Ignore Android outputs**

Ignore `.gradle/`, `omega-android/**/build/` and native generated libraries only
if they are produced artifacts.

- [ ] **Step 3: Run verification**

Run:

```powershell
cargo test -p omega-android-bridge
C:\Users\dima_\.gradle\wrapper\dists\gradle-8.13-bin\5xuhj0ry160q40clulazy9h7d\gradle-8.13\bin\gradle.bat -p omega-android :app:assembleDebug
```

Expected: Cargo tests pass. Android build passes when Android SDK is configured;
if no SDK is configured locally, record the exact Gradle failure.

