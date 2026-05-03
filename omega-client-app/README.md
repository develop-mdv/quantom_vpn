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

The main connection screen uses one field: a connection code. It accepts either
`omega://connect/<base64url-json>` or pasted `OMEGA_*` env text, then saves the
connection as a selectable profile.

## Build

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1
```

Use `-SkipRustBuild` only when `target/release/omega-client.exe` already exists.

## Outputs

- `omega-client-app/artifacts/windows-client/portable/OmegaVPN`
- `omega-client-app/artifacts/windows-client/installer`

The portable folder is for testing. The installer folder contains
`Omega.Client.Setup.exe` and `payload/`; run the setup executable as
administrator to install into `%ProgramFiles%\Omega VPN`.
