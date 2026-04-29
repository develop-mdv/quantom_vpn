# Windows Client App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Windows WPF GUI that launches and controls the existing Omega VPN runtime, with portable and installer packaging.

**Architecture:** Add a separate .NET WPF app under `omega-client-app` and keep `omega-client` as the VPN runtime. Shared GUI logic lives in a .NET core library; the Rust runtime only gains an optional control-file shutdown hook so disconnect can run normal cleanup.

**Tech Stack:** Rust workspace, .NET 9 WPF, .NET console test harness, PowerShell packaging script, Windows Task Scheduler for elevated autostart.

---

### Task 1: Project Structure And Core Tests

**Files:**
- Create: `omega-client-app/Omega.Client.App.sln`
- Create: `omega-client-app/src/Omega.Client.App.Core/Omega.Client.App.Core.csproj`
- Create: `omega-client-app/src/Omega.Client.App/Omega.Client.App.csproj`
- Create: `omega-client-app/src/Omega.Client.Setup/Omega.Client.Setup.csproj`
- Create: `omega-client-app/tests/Omega.Client.App.Tests/Omega.Client.App.Tests.csproj`
- Create: `omega-client-app/tests/Omega.Client.App.Tests/Program.cs`

- [ ] **Step 1: Write failing tests**

Add console harness tests for:

- default settings generate minimal fast env;
- missing required fields return validation errors;
- diagnostics JSON maps to connected/degraded/error status;
- lifecycle store writes readable JSON;
- control file writer writes a stop command.

- [ ] **Step 2: Verify tests fail before implementation**

Run:

```powershell
dotnet run --project omega-client-app/tests/Omega.Client.App.Tests/Omega.Client.App.Tests.csproj
```

Expected: compile failure because core types do not exist yet.

- [ ] **Step 3: Implement core logic**

Add:

- `ConnectionSettings`;
- `ConnectionSettingsValidator`;
- `OmegaEnvironmentBuilder`;
- `ClientDiagnosticsSnapshot`;
- `DiagnosticsStatusMapper`;
- `LifecycleSnapshot`;
- `LifecycleStore`;
- `ControlFile`;
- `ClientPaths`.

- [ ] **Step 4: Verify tests pass**

Run:

```powershell
dotnet run --project omega-client-app/tests/Omega.Client.App.Tests/Omega.Client.App.Tests.csproj
```

Expected: all harness tests pass.

### Task 2: Graceful Runtime Stop

**Files:**
- Create: `omega-client/src/control.rs`
- Modify: `omega-client/src/main.rs`

- [ ] **Step 1: Write failing Rust test**

Add a test that writes a control JSON file and expects `ControlCommand::Stop`
from the parser.

- [ ] **Step 2: Verify test fails**

Run:

```powershell
cargo test -p omega-client control
```

Expected: compile failure or failing assertion because the control helper is not implemented.

- [ ] **Step 3: Implement optional control file watcher**

Read `OMEGA_CONTROL_PATH`. If set, race `tokio::signal::ctrl_c()` against a polling loop that detects a stop command. Both paths must fall through the existing `network::cleanup(...)` call.

- [ ] **Step 4: Verify runtime tests**

Run:

```powershell
cargo test -p omega-client control
```

Expected: control tests pass.

### Task 3: WPF App

**Files:**
- Create: `omega-client-app/src/Omega.Client.App/App.xaml`
- Create: `omega-client-app/src/Omega.Client.App/App.xaml.cs`
- Create: `omega-client-app/src/Omega.Client.App/MainWindow.xaml`
- Create: `omega-client-app/src/Omega.Client.App/MainWindow.xaml.cs`
- Create: `omega-client-app/src/Omega.Client.App/app.manifest`

- [ ] **Step 1: Build UI around core logic**

The main window must show connection fields, status, connect/disconnect button,
diagnostic metrics, advanced settings, and log path.

- [ ] **Step 2: Add elevated manifest and tray**

Use `requireAdministrator` in the manifest and `System.Windows.Forms.NotifyIcon`
for tray status and show/connect/disconnect/exit menu actions.

- [ ] **Step 3: Verify WPF build**

Run:

```powershell
dotnet build omega-client-app/Omega.Client.App.sln
```

Expected: solution builds.

### Task 4: Installer And Packaging

**Files:**
- Create: `omega-client-app/src/Omega.Client.Setup/Program.cs`
- Create: `omega-client-app/src/Omega.Client.Setup/app.manifest`
- Create: `omega-client-app/package-windows-client.ps1`
- Create: `omega-client-app/README.md`

- [ ] **Step 1: Implement installer executable**

The setup app copies `payload` into `%ProgramFiles%\Omega VPN`, creates Desktop
and Start Menu shortcuts, and creates/removes the elevated scheduled task.

- [ ] **Step 2: Implement packaging script**

The script builds `omega-client`, publishes WPF app and setup app, copies
`wintun.dll`, creates portable and installer artifact folders, and writes a
portable README.

- [ ] **Step 3: Verify packaging command**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1 -SkipRustBuild
```

Expected: artifact folders are created when `target/release/omega-client.exe`
is already present; otherwise the script explains the missing runtime binary.

### Task 5: Documentation And Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/OPERATIONS.md`
- Modify: `docs/REPO_MAP.md`
- Modify: `.gitignore`

- [ ] **Step 1: Document GUI usage**

Add concise instructions for portable usage, installer usage, required fields,
and diagnostics.

- [ ] **Step 2: Run verification**

Run:

```powershell
dotnet run --project omega-client-app/tests/Omega.Client.App.Tests/Omega.Client.App.Tests.csproj
dotnet build omega-client-app/Omega.Client.App.sln
cargo test -p omega-client
```

Expected: all commands exit successfully.

## Self-Review

Spec coverage:

- Minimal GUI fields are covered by Task 3.
- Existing runtime isolation is covered by Tasks 1-3.
- Graceful disconnect is covered by Task 2.
- Portable and installer outputs are covered by Task 4.
- Documentation and verification are covered by Task 5.

Placeholder scan:

- The plan contains no intentionally deferred implementation sections.

Type consistency:

- Core names are stable across tasks: `ConnectionSettings`, `OmegaEnvironmentBuilder`,
  `ClientDiagnosticsSnapshot`, `LifecycleStore`, and `ControlFile`.
