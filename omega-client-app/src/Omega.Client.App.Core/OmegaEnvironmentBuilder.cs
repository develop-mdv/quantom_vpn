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

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["OMEGA_SERVER"] = settings.ServerEndpoint.Trim(),
            ["OMEGA_DEVICE_ID"] = settings.DeviceId.Trim(),
            ["OMEGA_DEVICE_TOKEN"] = settings.DeviceToken.Trim(),
            ["OMEGA_DEVICE_NAME"] = deviceName,
            ["OMEGA_PLATFORM"] = "windows",
            ["OMEGA_PROFILE"] = Normalize(settings.Profile, "gaming"),
            ["OMEGA_TRANSPORT"] = Normalize(settings.Transport, "auto"),
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
    }

    private static string Normalize(string? value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim().ToLowerInvariant();
    }
}
