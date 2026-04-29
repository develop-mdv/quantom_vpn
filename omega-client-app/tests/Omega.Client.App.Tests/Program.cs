using Omega.Client.App.Core;

var tests = new (string Name, Action Body)[]
{
    ("default settings generate fast env", DefaultSettingsGenerateFastEnvironment),
    ("validation requires minimum fields", ValidationRequiresMinimumFields),
    ("diagnostics map connected and degraded status", DiagnosticsMapStatus),
    ("diagnostics keep handshake connected state as connecting", DiagnosticsKeepIntermediateConnectedAsConnecting),
    ("lifecycle store writes readable json", LifecycleStoreWritesJson),
    ("control file writes stop command", ControlFileWritesStopCommand),
    ("config store round trips settings", ConfigStoreRoundTripsSettings),
    ("runtime launch plan is hidden and env driven", RuntimeLaunchPlanIsHiddenAndEnvDriven),
    ("window close hides to tray while runtime is active", WindowCloseHidesToTrayWhileRuntimeIsActive),
    ("autostart task builds scheduler arguments", AutostartTaskBuildsSchedulerArguments),
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

static void ConfigStoreRoundTripsSettings()
{
    var root = Path.Combine(Path.GetTempPath(), "omega-config-test-" + Guid.NewGuid().ToString("N"));
    var paths = ClientPaths.ForPortableRoot(root);
    var store = new ConfigStore(paths);
    var expected = new ConnectionSettings
    {
        ServerEndpoint = "198.51.100.10:443",
        DeviceId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        DeviceToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        DeviceName = "workstation",
        Transport = "tcp",
        Autostart = true,
    };

    store.Save(expected);
    var actual = store.Load();

    Equal(expected.ServerEndpoint, actual.ServerEndpoint);
    Equal(expected.DeviceId, actual.DeviceId);
    Equal(expected.DeviceToken, actual.DeviceToken);
    Equal(expected.DeviceName, actual.DeviceName);
    Equal(expected.Transport, actual.Transport);
    Equal(expected.Autostart, actual.Autostart);
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
