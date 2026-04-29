# Windows Client App Design

## Goal

Build a simple Windows GUI for Omega VPN so users no longer edit `.env` or run
`start_client.bat` directly. The app must keep the existing Rust VPN runtime
stable, expose only the minimum connection fields by default, support connect
and disconnect buttons, and ship as both a portable folder and an installer.

## Chosen Approach

Use a native WPF/.NET desktop app in `omega-client-app` as a thin controller
around the existing `omega-client.exe`.

The GUI is responsible for:

- storing user settings in JSON;
- generating the `OMEGA_*` environment for the runtime process;
- launching `omega-client.exe` elevated and without a console window;
- asking the runtime to stop gracefully;
- reading `omega-client/state/diagnostics.json`;
- showing a minimal status screen and tray icon;
- packaging portable and installable Windows builds.

The Rust runtime remains responsible for:

- handshake;
- TUN/Wintun setup;
- routes, DNS, IPv6 and kill switch behavior;
- encrypted datapath;
- diagnostics snapshot.

This keeps the working VPN behavior intact and adds only one small runtime
extension: an optional control file so the GUI can request a graceful shutdown
without killing the process and skipping route/DNS cleanup.

## User Experience

The main window starts with a compact connection panel:

- server endpoint;
- device id;
- device token;
- connect/disconnect button;
- current status;
- path quality, RTT, MTU, transport and tunnel IP when available.

Advanced settings stay collapsed:

- device name;
- transport: `auto`, `udp`, `tcp`;
- autostart;
- DNS leak guard;
- kill switch.

Defaults favor a fast universal setup:

- `OMEGA_PROFILE=gaming`;
- `OMEGA_TRANSPORT=auto`;
- `OMEGA_MTU_POLICY=auto`;
- `OMEGA_TUNNEL_MODE=full`;
- `OMEGA_DNS_POLICY=tunnel`;
- `OMEGA_IPV6_POLICY=tunnel`;
- `OMEGA_KILL_SWITCH=soft`;
- `OMEGA_DNS_LEAK_GUARD=warn`;
- `OMEGA_NETWORK_DIAG=1`.

The app requests administrator rights at startup because Wintun, routes, DNS
and the Windows kill switch need elevation.

## Files And Boundaries

`omega-client-app/src/Omega.Client.App.Core`

Core logic with no WPF dependency:

- connection settings;
- settings validation;
- environment generation;
- diagnostics parsing;
- lifecycle persistence;
- runtime process launch and graceful stop helpers;
- installer/autostart command helpers where they are testable without touching
  the system.

`omega-client-app/src/Omega.Client.App`

WPF UI:

- main window;
- tray icon;
- status polling;
- connect/disconnect commands;
- collapsed advanced settings.

`omega-client-app/src/Omega.Client.Setup`

Small installer executable:

- runs elevated;
- copies the portable payload to `%ProgramFiles%\Omega VPN`;
- creates Start Menu and Desktop shortcuts;
- creates/removes a scheduled task for elevated autostart.

`omega-client-app/tests/Omega.Client.App.Tests`

No external test framework. A small console test harness verifies core logic
with plain assertions so the project can build offline.

`omega-client/src/control.rs`

Minimal Rust helper for the optional stop control file.

## Error Handling

The GUI maps runtime state into user-facing messages:

- missing server/device/token;
- missing `omega-client.exe`;
- missing `wintun.dll`;
- handshake timeout;
- routing failure;
- degraded diagnostics;
- already running client process.

Detailed diagnostics remain available through `diagnostics.json` and the
runtime log file captured by the GUI.

## Packaging

Portable packaging produces an `artifacts/windows-client/portable/OmegaVPN`
folder containing:

- `Omega.Client.App.exe`;
- `omega-client.exe`;
- `wintun.dll`;
- default state directories;
- a README.

Installer packaging produces an `artifacts/windows-client/installer` folder
containing:

- `Omega.Client.Setup.exe`;
- `payload/` with the same portable app payload.

The installer copies the payload into `%ProgramFiles%\Omega VPN`, creates
shortcuts, and enables elevated autostart through Windows Task Scheduler when
requested.

## Verification

Required verification before completion:

- `dotnet run --project omega-client-app/tests/Omega.Client.App.Tests`;
- `dotnet build omega-client-app/Omega.Client.App.sln`;
- `cargo test -p omega-client`;
- package script dry run or normal run when local toolchain allows it.
