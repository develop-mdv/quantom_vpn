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
        if (!File.Exists(paths.ConfigPath))
        {
            return new ConnectionSettings();
        }

        try
        {
            var json = File.ReadAllText(paths.ConfigPath);
            return JsonSerializer.Deserialize<ConnectionSettings>(json, JsonOptions.Default)
                ?? new ConnectionSettings();
        }
        catch (JsonException)
        {
            return new ConnectionSettings();
        }
        catch (IOException)
        {
            return new ConnectionSettings();
        }
        catch (UnauthorizedAccessException)
        {
            return new ConnectionSettings();
        }
    }

    public void Save(ConnectionSettings settings)
    {
        Directory.CreateDirectory(paths.StateDirectory);
        File.WriteAllText(paths.ConfigPath, JsonSerializerDefaults.Write(settings));
    }
}
