using System.Text.Json.Serialization;

namespace Omega.Client.App.Core;

public static class ControlFile
{
    public static void RequestStop(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, JsonSerializerDefaults.Write(new ControlCommandRequest()));
    }
}

public sealed class ControlCommandRequest
{
    [JsonPropertyName("command")]
    public string Command { get; set; } = "stop";

    [JsonPropertyName("created_at_ms")]
    public long CreatedAtMs { get; set; } = Time.NowMs();
}
