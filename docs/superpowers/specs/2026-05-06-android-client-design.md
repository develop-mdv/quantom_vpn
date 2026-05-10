# Android Client Design

## Goal

Add a native Android client for Omega VPN. The app must let a user connect with
an Omega connection code, run the existing Omega protocol through Rust native
code, and expose Android per-app split tunneling so selected apps can bypass the
VPN or be the only apps routed through it.

## Chosen Approach

Use a Kotlin Android app in `omega-android/` with a Rust JNI/NDK bridge. Kotlin
owns Android platform responsibilities: `VpnService` permission flow, foreground
service lifecycle, TUN creation, notification, installed-app selection, settings
storage and UI. Rust owns Omega protocol responsibilities: handshake, ML-KEM
auth, flow/session key derivation, encrypted RTP/Omega datapath, ARQ/NACK,
keepalive and MTU probing.

This avoids a risky Kotlin reimplementation of the custom wire protocol.

## Android VPN Flow

The Android runtime must be two phase:

1. Kotlin starts native handshake with the saved server/device profile.
2. Rust performs Omega handshake and returns assigned TUN parameters: IPv4
   address, optional IPv6 address, MTU and DNS defaults.
3. Kotlin builds the VPN interface with `VpnService.Builder`, applies routes,
   DNS and app allow/deny rules, then calls `establish()`.
4. Kotlin passes the established TUN file descriptor to Rust.
5. Rust continues the existing datapath using `tun_rs::AsyncDevice::from_fd`.

The current desktop client cannot simply be launched on Android because it
creates/configures the TUN device itself. Android requires the VPN interface to
be created through `VpnService.Builder`.

## Split Tunneling

The app exposes two modes:

- `Exclude selected apps`: all traffic uses Omega except selected apps.
- `Only selected apps`: only selected apps use Omega; all other apps behave as
  if the VPN is not running.

The app always prevents the Omega Android package itself from entering the VPN
to avoid tunneling its own control connection back into the TUN interface. In
exclude mode this is done by adding the app package to the disallowed set. In
only-selected mode the app package is not allowed and the UI prevents selecting
it.

Android supports these behaviors through `addDisallowedApplication` and
`addAllowedApplication`. Android only allows one of these sets per VPN builder,
so the UI stores exactly one active split mode.

## Privacy Boundary

The app must not claim that VPN usage is undetectable for apps whose traffic is
routed through the VPN. Android exposes VPN transport information through
network capabilities. What the app can do correctly is keep chosen apps outside
the VPN so their networking behaves as if the VPN is not running.

## UI

The first screen is the usable VPN client, not a marketing page:

- connection status;
- connect/disconnect control;
- connection code/server/device fields;
- compact path summary;
- split tunneling mode switch;
- searchable installed-app list.

The visual style is quiet and utility-focused: dark graphite base, teal/green
connection state, compact grouped controls and a simple Omega shield identity.
The project includes deterministic vector assets for buildability; generated
bitmap logo exploration can be copied into Android mipmap assets when selected.

## Files And Boundaries

`omega-android/settings.gradle.kts`

Android project settings.

`omega-android/build.gradle.kts`

Top-level Android/Kotlin plugin declarations.

`omega-android/app/build.gradle.kts`

Android app module, Kotlin settings and native library packaging.

`omega-android/app/src/main/AndroidManifest.xml`

Permissions, `MainActivity` and `OmegaVpnService` registration.

`omega-android/app/src/main/java/vpn/myboroda/omega/*`

Kotlin app code: profile parsing/storage, UI, app selection and VPN service.

`omega-android/app/src/main/res/*`

Vector logo, colors, strings, notification icon and launcher resources.

`omega-android/native/README.md`

How to build and copy native `.so` artifacts for Android ABIs.

`omega-android-bridge/`

Rust cdylib crate for JNI entrypoints and host-testable bridge config parsing.

`omega-client/`

Later runtime extraction point for the two-phase native client flow. The
Android bridge must reuse this behavior instead of reimplementing the protocol.

## Error Handling

The UI shows short user-facing states:

- VPN permission required;
- invalid or missing connection profile;
- native library missing;
- handshake failed;
- TUN setup failed;
- split-tunnel package not installed;
- connected;
- disconnected.

Detailed native errors are returned through the bridge as strings and written to
Android logcat.

## Verification

Required local checks:

- `cargo test -p omega-android-bridge`;
- Android Gradle build when an Android SDK is available;
- Android Studio/emulator manual check for VPN permission and split rules;
- server integration check with a registered Android device code.

