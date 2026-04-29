using System.Text.Json.Serialization;

namespace Omega.Client.App.Core;

public sealed class LifecycleSnapshot
{
    [JsonPropertyName("state")]
    public string State { get; set; } = "disconnected";

    [JsonPropertyName("started_at_ms")]
    public long StartedAtMs { get; set; } = Time.NowMs();

    [JsonPropertyName("updated_at_ms")]
    public long UpdatedAtMs { get; set; } = Time.NowMs();

    [JsonPropertyName("pid")]
    public int? Pid { get; set; }

    [JsonPropertyName("server_endpoint")]
    public string ServerEndpoint { get; set; } = "";

    [JsonPropertyName("device_name")]
    public string DeviceName { get; set; } = "";

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("last_error")]
    public string? LastError { get; set; }
}

public sealed class LifecycleStore
{
    private readonly ClientPaths paths;

    public LifecycleStore(ClientPaths paths)
    {
        this.paths = paths;
    }

    public void Write(LifecycleSnapshot snapshot)
    {
        Directory.CreateDirectory(paths.StateDirectory);
        snapshot.UpdatedAtMs = Time.NowMs();
        File.WriteAllText(paths.LifecyclePath, JsonSerializerDefaults.Write(snapshot));
    }
}
