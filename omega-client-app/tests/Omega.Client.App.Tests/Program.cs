using Omega.Client.App.Core;

var tests = new (string Name, Action Body)[]
{
    ("default settings generate fast env", DefaultSettingsGenerateFastEnvironment),
    ("validation requires minimum fields", ValidationRequiresMinimumFields),
    ("diagnostics map connected and degraded status", DiagnosticsMapStatus),
    ("diagnostics keep handshake connected state as connecting", DiagnosticsKeepIntermediateConnectedAsConnecting),
    ("lifecycle store writes readable json", LifecycleStoreWritesJson),
    ("control file writes stop command", ControlFileWritesStopCommand),
    ("connection code parses compact omega url", ConnectionCodeParsesCompactOmegaUrl),
    ("connection code parses env paste", ConnectionCodeParsesEnvPaste),
    ("config store migrates legacy settings into saved profile", ConfigStoreMigratesLegacySettingsIntoSavedProfile),
    ("config store round trips saved profiles", ConfigStoreRoundTripsSavedProfiles),
    ("runtime launch plan is hidden and env driven", RuntimeLaunchPlanIsHiddenAndEnvDriven),
    ("window close hides to tray while runtime is active", WindowCloseHidesToTrayWhileRuntimeIsActive),
    ("autostart task builds scheduler arguments", AutostartTaskBuildsSchedulerArguments),
    ("windows bootstrap installer documents required commands", WindowsBootstrapInstallerDocumentsRequiredCommands),
};

var failed = 0;
foreach (var test in tests)
{
    try
    {
        test.Body();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {test.Name}: {ex.Message}");
    }
}

if (failed > 0)
{
    Console.Error.WriteLine($"{failed} test(s) failed.");
    return 1;
}

Console.WriteLine($"{tests.Length} test(s) passed.");
return 0;

static void DefaultSettingsGenerateFastEnvironment()
{
    var settings = new ConnectionSettings
    {
        ServerEndpoint = "203.0.113.1:443",
        DeviceId = "11111111-2222-3333-4444-555555555555",
        DeviceToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        DeviceName = "home-pc",
    };
    var paths = ClientPaths.ForPortableRoot(Path.Combine(Path.GetTempPath(), "omega-env-test"));

    var env = OmegaEnvironmentBuilder.Build(settings, paths);

    Equal("203.0.113.1:443", env["OMEGA_SERVER"]);
    Equal("11111111-2222-3333-4444-555555555555", env["OMEGA_DEVICE_ID"]);
    Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", env["OMEGA_DEVICE_TOKEN"]);
    Equal("home-pc", env["OMEGA_DEVICE_NAME"]);
    Equal("windows", env["OMEGA_PLATFORM"]);
    Equal("gaming", env["OMEGA_PROFILE"]);
    Equal("auto", env["OMEGA_TRANSPORT"]);
    Equal("auto", env["OMEGA_MTU_POLICY"]);
    Equal("full", env["OMEGA_TUNNEL_MODE"]);
    Equal("tunnel", env["OMEGA_DNS_POLICY"]);
    Equal("tunnel", env["OMEGA_IPV6_POLICY"]);
    Equal("soft", env["OMEGA_KILL_SWITCH"]);
    Equal("warn", env["OMEGA_DNS_LEAK_GUARD"]);
    Equal("1", env["OMEGA_NETWORK_DIAG"]);
    Equal(paths.DiagnosticsPath, env["OMEGA_DIAGNOSTICS_PATH"]);
    Equal(paths.ControlPath, env["OMEGA_CONTROL_PATH"]);
}

static void ValidationRequiresMinimumFields()
{
    var errors = ConnectionSettingsValidator.Validate(new ConnectionSettings());

    True(errors.Any(error => error.Field == nameof(ConnectionSettings.ServerEndpoint)), "server endpoint error missing");
    True(errors.Any(error => error.Field == nameof(ConnectionSettings.DeviceId)), "device id error missing");
    True(errors.Any(error => error.Field == nameof(ConnectionSettings.DeviceToken)), "device token error missing");
}

static void DiagnosticsMapStatus()
{
    var healthyJson = """
    {
      "status": "connected_healthy",
      "server_endpoint": "203.0.113.1:443",
      "device_name": "home-pc",
      "transport_policy": "udp",
      "effective_mtu": 1380,
      "handshake_rtt_ms": 47,
      "tunnel_ip": "10.7.0.2",
      "path_quality": "good",
      "suspected_issue": null
    }
    """;
    var healthy = ClientDiagnosticsSnapshot.FromJson(healthyJson);
    var healthyView = DiagnosticsStatusMapper.ToView(healthy);
    Equal(ConnectionDisplayState.Connected, healthyView.State);
    Equal("good", healthyView.PathQuality);
    Equal("47 ms", healthyView.HandshakeRtt);

    var degradedJson = healthyJson.Replace("connected_healthy", "connected_degraded").Replace("good", "poor");
    var degraded = ClientDiagnosticsSnapshot.FromJson(degradedJson);
    Equal(ConnectionDisplayState.Degraded, DiagnosticsStatusMapper.ToView(degraded).State);
}

static void DiagnosticsKeepIntermediateConnectedAsConnecting()
{
    var intermediateJson = """
    {
      "status": "connected",
      "server_endpoint": "203.0.113.1:443",
      "device_name": "home-pc",
      "transport_policy": "udp",
      "effective_mtu": 1380,
      "handshake_rtt_ms": 47,
      "tunnel_ip": "10.7.0.2",
      "path_quality": "fair",
      "suspected_issue": null
    }
    """;

    var view = DiagnosticsStatusMapper.ToView(ClientDiagnosticsSnapshot.FromJson(intermediateJson));

    Equal(ConnectionDisplayState.Connecting, view.State);
    True(!view.StatusText.Contains("Connected", StringComparison.OrdinalIgnoreCase), "intermediate state must not say connected");
}

static void LifecycleStoreWritesJson()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-lifecycle-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);
    var store = new LifecycleStore(paths);

    store.Write(new LifecycleSnapshot
    {
        State = "connecting",
        Pid = 1234,
        ServerEndpoint = "203.0.113.1:443",
        DeviceName = "home-pc",
        Profile = "gaming",
        Message = "Starting Omega VPN",
    });

    var raw = File.ReadAllText(paths.LifecyclePath);
    True(raw.Contains("\"state\": \"connecting\"", StringComparison.Ordinal), "state was not written");
    True(raw.Contains("\"pid\": 1234", StringComparison.Ordinal), "pid was not written");
}

static void ControlFileWritesStopCommand()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-control-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);

    ControlFile.RequestStop(paths.ControlPath);

    var raw = File.ReadAllText(paths.ControlPath);
    True(raw.Contains("\"command\": \"stop\"", StringComparison.Ordinal), "stop command was not written");
}

static void ConnectionCodeParsesCompactOmegaUrl()
{
    var expected = new ConnectionSettings
    {
        ServerEndpoint = "203.0.113.1:443",
        DeviceId = "11111111-2222-3333-4444-555555555555",
        DeviceToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        DeviceName = "office-pc",
        Transport = "auto",
    };

    var code = ConnectionCode.Create(expected, "Office");
    var parsed = ConnectionCodeParser.Parse(code);

    True(parsed.Success, parsed.ErrorMessage ?? "connection code failed");
    Equal("Office", parsed.ProfileName);
    Equal(expected.ServerEndpoint, parsed.Settings!.ServerEndpoint);
    Equal(expected.DeviceId, parsed.Settings.DeviceId);
    Equal(expected.DeviceToken, parsed.Settings.DeviceToken);
    Equal(expected.DeviceName, parsed.Settings.DeviceName);
    Equal("tunnel", parsed.Settings.Ipv6Policy);
}

static void ConnectionCodeParsesEnvPaste()
{
    var code = """
    OMEGA_SERVER=198.51.100.10:443
    OMEGA_DEVICE_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    OMEGA_DEVICE_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    OMEGA_DEVICE_NAME=Home Laptop
    OMEGA_TRANSPORT=tcp
    """;

    var parsed = ConnectionCodeParser.Parse(code);

    True(parsed.Success, parsed.ErrorMessage ?? "env paste failed");
    Equal("198.51.100.10:443", parsed.Settings!.ServerEndpoint);
    Equal("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", parsed.Settings.DeviceId);
    Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", parsed.Settings.DeviceToken);
    Equal("Home Laptop", parsed.Settings.DeviceName);
    Equal("tcp", parsed.Settings.Transport);
}

static void ConfigStoreMigratesLegacySettingsIntoSavedProfile()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-config-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);
    Directory.CreateDirectory(paths.StateDirectory);
    var legacy = new ConnectionSettings
    {
        ServerEndpoint = "198.51.100.10:443",
        DeviceId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        DeviceToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        DeviceName = "workstation",
        Transport = "tcp",
        Autostart = true,
    };
    File.WriteAllText(paths.ConfigPath, $$"""
    {
      "server_endpoint": "{{legacy.ServerEndpoint}}",
      "device_id": "{{legacy.DeviceId}}",
      "device_token": "{{legacy.DeviceToken}}",
      "device_name": "{{legacy.DeviceName}}",
      "transport": "{{legacy.Transport}}",
      "autostart": true
    }
    """);

    var store = new ConfigStore(paths);
    var state = store.LoadState();

    Equal(1, state.Profiles.Count);
    Equal(state.Profiles[0].Id, state.SelectedProfileId);
    Equal("workstation", state.Profiles[0].Name);
    Equal(legacy.ServerEndpoint, state.Profiles[0].Settings.ServerEndpoint);
    Equal(legacy.DeviceToken, state.Profiles[0].Settings.DeviceToken);
}

static void ConfigStoreRoundTripsSavedProfiles()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-config-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);
    var store = new ConfigStore(paths);
    var expected = new ClientAppConfig
    {
        SelectedProfileId = "profile-2",
        Profiles =
        [
            SavedConnectionProfile.FromSettings("Office", new ConnectionSettings
            {
                ServerEndpoint = "198.51.100.10:443",
                DeviceId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                DeviceToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }, "profile-1"),
            SavedConnectionProfile.FromSettings("Home", new ConnectionSettings
            {
                ServerEndpoint = "203.0.113.1:443",
                DeviceId = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                DeviceToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            }, "profile-2"),
        ],
    };

    store.SaveState(expected);
    var actual = store.LoadState();

    Equal(2, actual.Profiles.Count);
    Equal("profile-2", actual.SelectedProfileId);
    Equal("Office", actual.Profiles[0].Name);
    Equal("Home", actual.Profiles[1].Name);
    Equal("203.0.113.1:443", actual.Profiles[1].Settings.ServerEndpoint);
}

static void RuntimeLaunchPlanIsHiddenAndEnvDriven()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-launch-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);
    var settings = new ConnectionSettings
    {
        ServerEndpoint = "203.0.113.1:443",
        DeviceId = "11111111-2222-3333-4444-555555555555",
        DeviceToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };

    var startInfo = RuntimeLaunchPlan.Create(settings, paths);

    Equal(paths.RuntimeExePath, startInfo.FileName);
    Equal(paths.RootPath, startInfo.WorkingDirectory);
    Equal(false, startInfo.UseShellExecute);
    Equal(true, startInfo.CreateNoWindow);
    Equal(true, startInfo.RedirectStandardOutput);
    Equal(true, startInfo.RedirectStandardError);
    Equal("203.0.113.1:443", startInfo.Environment["OMEGA_SERVER"]);
    Equal(paths.ControlPath, startInfo.Environment["OMEGA_CONTROL_PATH"]);
}

static void WindowCloseHidesToTrayWhileRuntimeIsActive()
{
    Equal(
        WindowCloseAction.HideToTray,
        WindowClosePolicy.Decide(hasActiveRuntime: true, explicitExitRequested: false));
    Equal(
        WindowCloseAction.ExitApplication,
        WindowClosePolicy.Decide(hasActiveRuntime: true, explicitExitRequested: true));
    Equal(
        WindowCloseAction.ExitApplication,
        WindowClosePolicy.Decide(hasActiveRuntime: false, explicitExitRequested: false));
}

static void AutostartTaskBuildsSchedulerArguments()
{
    var createArgs = AutostartTask.BuildCreateArguments(@"C:\Program Files\Omega VPN\Omega.Client.App.exe");
    Equal("/Create", createArgs[0]);
    True(createArgs.Contains("/TN"), "task name flag missing");
    True(createArgs.Contains("Omega VPN"), "task name missing");
    True(createArgs.Contains("/RL"), "run level flag missing");
    True(createArgs.Contains("HIGHEST"), "highest run level missing");
    True(createArgs.Any(arg => arg.Contains("Omega.Client.App.exe", StringComparison.Ordinal)), "target path missing");

    var deleteArgs = AutostartTask.BuildDeleteArguments();
    Equal("/Delete", deleteArgs[0]);
    True(deleteArgs.Contains("/F"), "force delete flag missing");
}

static void WindowsBootstrapInstallerDocumentsRequiredCommands()
{
    var scriptPath = Path.Combine(FindRepoRoot(), "install-windows-client.ps1");
    True(File.Exists(scriptPath), "root install-windows-client.ps1 is missing");

    var script = File.ReadAllText(scriptPath);
    True(script.Contains("Microsoft.DotNet.SDK.9", StringComparison.Ordinal), ".NET 9 SDK winget package missing");
    True(script.Contains("Rustlang.Rustup", StringComparison.Ordinal), "rustup winget package missing");
    True(script.Contains("Microsoft.VisualStudio.2022.BuildTools", StringComparison.Ordinal), "C++ build tools winget package missing");
    True(script.Contains("omega-client-app/package-windows-client.ps1", StringComparison.Ordinal), "package script invocation missing");
    True(script.Contains("Omega.Client.Setup.exe", StringComparison.Ordinal), "setup executable launch missing");
    True(script.Contains("SkipDependencyInstall", StringComparison.Ordinal), "dependency install opt-out parameter missing");
    True(script.Contains("SkipRustBuild", StringComparison.Ordinal), "rust build opt-out parameter missing");
}

static string FindRepoRoot()
{
    var directory = new DirectoryInfo(AppContext.BaseDirectory);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "Cargo.toml")) &&
            Directory.Exists(Path.Combine(directory.FullName, "omega-client-app")))
        {
            return directory.FullName;
        }

        directory = directory.Parent;
    }

    throw new InvalidOperationException("repository root not found");
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"expected '{expected}', got '{actual}'");
    }
}

static void True(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
