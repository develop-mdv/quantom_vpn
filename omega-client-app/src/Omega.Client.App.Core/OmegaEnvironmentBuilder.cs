namespace Omega.Client.App.Core;

public static class OmegaEnvironmentBuilder
{
    public static IReadOnlyDictionary<string, string> Build(ConnectionSettings settings, ClientPaths paths)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(paths);

        var deviceName = string.IsNullOrWhiteSpace(settings.DeviceName)
            ? Environment.MachineName
            : settings.DeviceName.Trim();

        // The REALITY toggle overrides the transport selection: if the user
        // ticked "Включить обход (REALITY)" we force transport=reality so the
        // Rust client uses the connection code instead of UDP/TCP.
        var effectiveTransport = settings.RealityEnabled
            ? "reality"
            : Normalize(settings.Transport, "auto");

        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["OMEGA_SERVER"] = settings.ServerEndpoint.Trim(),
            ["OMEGA_DEVICE_ID"] = settings.DeviceId.Trim(),
            ["OMEGA_DEVICE_TOKEN"] = settings.DeviceToken.Trim(),
            ["OMEGA_DEVICE_NAME"] = deviceName,
            ["OMEGA_PLATFORM"] = "windows",
            ["OMEGA_PROFILE"] = Normalize(settings.Profile, "gaming"),
            ["OMEGA_TRANSPORT"] = effectiveTransport,
            ["OMEGA_MTU_POLICY"] = Normalize(settings.MtuPolicy, "auto"),
            ["OMEGA_TUNNEL_MODE"] = Normalize(settings.TunnelMode, "full"),
            ["OMEGA_DNS_POLICY"] = Normalize(settings.DnsPolicy, "tunnel"),
            ["OMEGA_DNS_SERVERS"] = Normalize(settings.DnsServers, "1.1.1.1,8.8.8.8"),
            ["OMEGA_IPV6_POLICY"] = Normalize(settings.Ipv6Policy, "tunnel"),
            ["OMEGA_KILL_SWITCH"] = Normalize(settings.KillSwitch, "soft"),
            ["OMEGA_DNS_LEAK_GUARD"] = Normalize(settings.DnsLeakGuard, "warn"),
            ["OMEGA_NETWORK_DIAG"] = settings.NetworkDiagnostics ? "1" : "0",
            ["OMEGA_DIAGNOSTICS_PATH"] = paths.DiagnosticsPath,
            ["OMEGA_CONTROL_PATH"] = paths.ControlPath,
            ["RUST_LOG"] = "info",
        };

        // REALITY: forward the single connection code. The Rust client only
        // consumes it when `OMEGA_TRANSPORT=reality` (which we set above
        // when the user flipped the toggle).
        if (!string.IsNullOrWhiteSpace(settings.RealityCode))
        {
            env["OMEGA_REALITY_CODE"] = settings.RealityCode.Trim();
        }
        return env;
    }

    private static string Normalize(string? value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant();
    }
}
