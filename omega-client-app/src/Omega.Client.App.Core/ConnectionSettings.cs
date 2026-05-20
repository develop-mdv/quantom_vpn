namespace Omega.Client.App.Core;

using System.Text.Json.Serialization;

public sealed class ConnectionSettings
{
    [JsonPropertyName("server_endpoint")]
    public string ServerEndpoint { get; set; } = "";

    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = "";

    [JsonPropertyName("device_token")]
    public string DeviceToken { get; set; } = "";

    [JsonPropertyName("device_name")]
    public string DeviceName { get; set; } = Environment.MachineName;

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "gaming";

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "auto";

    [JsonPropertyName("tunnel_mode")]
    public string TunnelMode { get; set; } = "full";

    [JsonPropertyName("mtu_policy")]
    public string MtuPolicy { get; set; } = "auto";

    [JsonPropertyName("dns_policy")]
    public string DnsPolicy { get; set; } = "tunnel";

    [JsonPropertyName("dns_servers")]
    public string DnsServers { get; set; } = "1.1.1.1,8.8.8.8";

    [JsonPropertyName("ipv6_policy")]
    public string Ipv6Policy { get; set; } = "tunnel";

    [JsonPropertyName("kill_switch")]
    public string KillSwitch { get; set; } = "soft";

    [JsonPropertyName("dns_leak_guard")]
    public string DnsLeakGuard { get; set; } = "warn";

    [JsonPropertyName("network_diagnostics")]
    public bool NetworkDiagnostics { get; set; } = true;

    [JsonPropertyName("autostart")]
    public bool Autostart { get; set; }

    // REALITY (XTLS-style TLS masquerade). Single self-contained code the
    // server admin pastes to the user. Format: omega-reality://<base64url-json>.
    // When `RealityEnabled` is true the client uses this code instead of UDP/TCP.

    [JsonPropertyName("reality_code")]
    public string RealityCode { get; set; } = "";

    [JsonPropertyName("reality_enabled")]
    public bool RealityEnabled { get; set; }

    public ConnectionSettings Clone()
    {
        return new ConnectionSettings
        {
            ServerEndpoint = ServerEndpoint,
            DeviceId = DeviceId,
            DeviceToken = DeviceToken,
            DeviceName = DeviceName,
            Profile = Profile,
            Transport = Transport,
            TunnelMode = TunnelMode,
            MtuPolicy = MtuPolicy,
            DnsPolicy = DnsPolicy,
            DnsServers = DnsServers,
            Ipv6Policy = Ipv6Policy,
            KillSwitch = KillSwitch,
            DnsLeakGuard = DnsLeakGuard,
            NetworkDiagnostics = NetworkDiagnostics,
            Autostart = Autostart,
            RealityCode = RealityCode,
            RealityEnabled = RealityEnabled,
        };
    }
}
