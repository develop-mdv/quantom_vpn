using System.Text.Json;

namespace Omega.Client.App.Core;

public sealed class ConfigStore
{
    private readonly ClientPaths paths;

    public ConfigStore(ClientPaths paths)
    {
        this.paths = paths;
    }

    public ConnectionSettings Load()
    {
        return LoadState().SelectedProfile()?.Settings.Clone()
            ?? new ConnectionSettings();
    }

    public ClientAppConfig LoadState()
    {
        if (!File.Exists(paths.ConfigPath))
        {
            return new ClientAppConfig();
        }

        try
        {
            var json = File.ReadAllText(paths.ConfigPath);
            return LoadFromJson(json);
        }
        catch (JsonException)
        {
            return new ClientAppConfig();
        }
        catch (IOException)
        {
            return new ClientAppConfig();
        }
        catch (UnauthorizedAccessException)
        {
            return new ClientAppConfig();
        }
    }

    public void Save(ConnectionSettings settings)
    {
        var state = new ClientAppConfig();
        state.UpsertProfile(settings);
        SaveState(state);
    }

    public void SaveState(ClientAppConfig state)
    {
        Directory.CreateDirectory(paths.StateDirectory);
        state.Normalize();
        File.WriteAllText(paths.ConfigPath, JsonSerializerDefaults.Write(state));
    }

    private static ClientAppConfig LoadFromJson(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind == JsonValueKind.Object
            && (document.RootElement.TryGetProperty("profiles", out _)
                || document.RootElement.TryGetProperty("schema_version", out _)))
        {
            var state = JsonSerializer.Deserialize<ClientAppConfig>(json, JsonOptions.Default)
                ?? new ClientAppConfig();
            state.Normalize();
            return state;
        }

        var legacy = JsonSerializer.Deserialize<ConnectionSettings>(json, JsonOptions.Default)
            ?? new ConnectionSettings();
        var migrated = new ClientAppConfig();
        if (!string.IsNullOrWhiteSpace(legacy.ServerEndpoint)
            || !string.IsNullOrWhiteSpace(legacy.DeviceId)
            || !string.IsNullOrWhiteSpace(legacy.DeviceToken))
        {
            migrated.UpsertProfile(legacy);
        }

        migrated.Normalize();
        return migrated;
    }
}
