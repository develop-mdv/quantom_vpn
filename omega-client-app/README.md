# Omega Windows Client App

`Omega.Client.App` is a native Windows GUI around the existing `omega-client`
runtime. It writes the required `OMEGA_*` environment, launches the runtime as
an elevated child process, reads diagnostics, and requests graceful disconnects
through `OMEGA_CONTROL_PATH`.

The desktop client uses `OMEGA_IPV6_POLICY=tunnel` by default so dual-stack
traffic is handled by the VPN when the server runs with IPv6 NAT enabled.

Portable and installer packages are published as self-contained Windows builds,
so users do not need to install the .NET Desktop Runtime separately.

Closing the main window while the VPN runtime is active hides the app to the
Windows tray. Use the tray menu to open the window again or exit after a
graceful disconnect.

Only one GUI instance runs per Windows session. Starting Omega VPN again brings
the existing window to the foreground, including when it is hidden in the tray.

The main connection screen uses one field: a connection code. It accepts either
`omega://connect/<base64url-json>` or pasted `OMEGA_*` env text, then saves the
connection as a selectable profile.

Installed clients keep profiles and runtime state in
`%LocalAppData%\Omega VPN\state`. Setup migrates the legacy
`%ProgramFiles%\Omega VPN\omega-client\state\app-config.json` on the first
update. Portable clients continue to use `omega-client\state` beside the app.
Installer payloads never contain an `app-config.json` from the build machine.

## Build Prerequisites

The build machine must have:

- Rust toolchain with `cargo` available in `PATH`.
- .NET 9 SDK.
- `wintun.dll` in the repository root.

Install Rust with `rustup` from `https://rustup.rs/`, choose the default stable
MSVC toolchain, then verify it:

```powershell
rustup --version
cargo --version
```

Install the .NET 9 SDK from `https://dotnet.microsoft.com/download/dotnet/9.0`
or with `winget`, then open a new PowerShell window and verify it:

```powershell
winget install --id Microsoft.DotNet.SDK.9 --source winget
dotnet --version
dotnet --list-sdks
```

Rust is required only to build `omega-client.exe`. A new user PC does not need
Rust or the .NET Desktop Runtime when you install from the ready
`installer` package.

## Build

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1
```

Use `-SkipRustBuild` only when `target/release/omega-client.exe` already exists.

If Rust finished but packaging failed with `dotnet : The term 'dotnet' is not
recognized`, install the .NET 9 SDK, reopen PowerShell so `PATH` is refreshed,
and rerun packaging without rebuilding Rust:

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1 -SkipRustBuild
```

If `dotnet` is still not recognized after installation, check that
`C:\Program Files\dotnet` is present in the system `PATH`.

## Outputs

- `omega-client-app/artifacts/windows-client/portable/OmegaVPN`
- `omega-client-app/artifacts/windows-client/installer`

The portable folder is for testing. The installer folder contains
`Omega.Client.Setup.exe` and `payload/`; run the setup executable as
administrator to install into `%ProgramFiles%\Omega VPN`.

## Install on a New Windows PC

Use the installer package for a normal user machine:

1. Build or download the `omega-client-app/artifacts/windows-client/installer`
   folder.
2. Copy the whole `installer` folder to the new PC. Keep
   `Omega.Client.Setup.exe` and `payload/` next to each other; the setup
   executable copies files from `payload/`.
3. Run `Omega.Client.Setup.exe`. It asks for administrator approval when
   needed, installs Omega VPN into `%ProgramFiles%\Omega VPN`, creates Desktop
   and Start menu shortcuts, and enables elevated autostart through Windows
   Task Scheduler.
4. Start `Omega VPN` from the shortcut.
5. Paste the connection code for this PC. The code can be an
   `omega://connect/...` link or pasted `OMEGA_*` environment text. After it is
   saved, the profile is available from the profile list.

To update, run `Omega.Client.Setup.exe` from the new installer folder. Setup
asks a running client to disconnect gracefully, stages the new version, swaps
the program directory, and keeps the profiles in `%LocalAppData%` unchanged.

For a new PC, create/register a separate Windows device and use its own
connection code. Reusing another machine's device token works only as a manual
migration choice and makes both installs share the same device identity.

Optional setup commands:

```powershell
.\Omega.Client.Setup.exe --no-autostart
.\Omega.Client.Setup.exe --target "D:\Apps\Omega VPN"
.\Omega.Client.Setup.exe uninstall
```

The portable package can be used without installation for quick tests: copy
`portable/OmegaVPN` to the PC and run `Omega.Client.App.exe` as administrator.
For day-to-day use, prefer the installer.
