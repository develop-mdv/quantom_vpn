using System.Text.Json;

namespace Omega.Client.App.Core;

internal static class JsonOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };
}

internal static class JsonSerializerDefaults
{
    public static string Write<T>(T value)
    {
        return JsonSerializer.Serialize(value, JsonOptions.Default);
    }
}
