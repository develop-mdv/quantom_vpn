using System.Text.Json;
using System.Text.Json.Serialization;

namespace Omega.Client.App.Core;

public enum ConnectionDisplayState
{
    Disconnected,
    Connecting,
    Connected,
    Degraded,
    Error,
    Stopping,
}

public sealed class ClientDiagnosticsSnapshot
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("server_endpoint")]
    public string? ServerEndpoint { get; set; }

    [JsonPropertyName("device_name")]
    public string? DeviceName { get; set; }

    [JsonPropertyName("transport_policy")]
    public string? TransportPolicy { get; set; }

    [JsonPropertyName("effective_mtu")]
    public int? EffectiveMtu { get; set; }

    [JsonPropertyName("handshake_rtt_ms")]
    public long? HandshakeRttMs { get; set; }

    [JsonPropertyName("tunnel_ip")]
    public string? TunnelIp { get; set; }

    [JsonPropertyName("tunnel_ipv6")]
    public string? TunnelIpv6 { get; set; }

    [JsonPropertyName("path_quality")]
    public string? PathQuality { get; set; }

    [JsonPropertyName("suspected_issue")]
    public string? SuspectedIssue { get; set; }

    public static ClientDiagnosticsSnapshot FromJson(string json)
    {
        return JsonSerializer.Deserialize<ClientDiagnosticsSnapshot>(json, JsonOptions.Default)
            ?? new ClientDiagnosticsSnapshot();
    }
}

public sealed record DiagnosticsView(
    ConnectionDisplayState State,
    string StatusText,
    string PathQuality,
    string HandshakeRtt,
    string EffectiveMtu,
    string Transport,
    string TunnelIp,
    string Message);

public static class DiagnosticsStatusMapper
{
    public static DiagnosticsView ToView(ClientDiagnosticsSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            return new DiagnosticsView(
                ConnectionDisplayState.Disconnected,
                "Disconnected",
                "n/a",
                "n/a",
                "n/a",
                "n/a",
                "n/a",
                "Omega VPN is not connected.");
        }

        var state = MapState(snapshot.Status);
        var statusText = state switch
        {
            ConnectionDisplayState.Connected => "Подключено",
            ConnectionDisplayState.Degraded => "Есть предупреждения",
            ConnectionDisplayState.Connecting => "Подключение",
            ConnectionDisplayState.Stopping => "Отключение",
            ConnectionDisplayState.Error => "Ошибка подключения",
            _ => "Отключено",
        };

        return new DiagnosticsView(
            state,
            statusText,
            ValueOrDefault(snapshot.PathQuality),
            snapshot.HandshakeRttMs is long rtt ? $"{rtt} ms" : "n/a",
            snapshot.EffectiveMtu is int mtu ? mtu.ToString() : "n/a",
            ValueOrDefault(snapshot.TransportPolicy),
            ValueOrDefault(snapshot.TunnelIp),
            UserMessage(snapshot, state, statusText));
    }

    private static ConnectionDisplayState MapState(string? status)
    {
        return status?.Trim().ToLowerInvariant() switch
        {
            "connected_healthy" => ConnectionDisplayState.Connected,
            "connected_degraded" => ConnectionDisplayState.Degraded,
            "starting" or "handshaking" or "routing" or "connecting" or "connected" => ConnectionDisplayState.Connecting,
            "stopping" => ConnectionDisplayState.Stopping,
            "failed" or "routing_failed" or "server_closed" => ConnectionDisplayState.Error,
            _ => ConnectionDisplayState.Disconnected,
        };
    }

    private static string UserMessage(
        ClientDiagnosticsSnapshot snapshot,
        ConnectionDisplayState state,
        string statusText)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.SuspectedIssue))
        {
            return snapshot.SuspectedIssue.Trim();
        }

        return snapshot.Status?.Trim().ToLowerInvariant() switch
        {
            "connected" => "Handshake прошел, идет настройка маршрутов и проверка подключения.",
            "routing_failed" => "Не удалось настроить маршруты Windows. Откройте журнал runtime.log для деталей.",
            "connected_degraded" => "Туннель поднят, но одна из проверок качества или DNS не прошла.",
            "handshaking" => "Идет защищенное подключение к серверу.",
            "starting" => "Omega VPN запускается.",
            _ => state == ConnectionDisplayState.Connected ? "VPN подключен и проверки прошли." : statusText,
        };
    }

    private static string ValueOrDefault(string? value, string fallback = "n/a")
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    }
}
