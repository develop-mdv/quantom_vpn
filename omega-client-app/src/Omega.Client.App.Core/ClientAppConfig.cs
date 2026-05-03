using System.Text.Json.Serialization;

namespace Omega.Client.App.Core;

public sealed class ClientAppConfig
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; } = 2;

    [JsonPropertyName("selected_profile_id")]
    public string SelectedProfileId { get; set; } = "";

    [JsonPropertyName("profiles")]
    public List<SavedConnectionProfile> Profiles { get; set; } = [];

    public SavedConnectionProfile? SelectedProfile()
    {
        return Profiles.FirstOrDefault(profile => string.Equals(profile.Id, SelectedProfileId, StringComparison.Ordinal))
            ?? Profiles.FirstOrDefault();
    }

    public SavedConnectionProfile UpsertProfile(ConnectionSettings settings, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var existing = Profiles.FirstOrDefault(profile =>
            string.Equals(profile.Settings.DeviceId, settings.DeviceId, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            existing = SavedConnectionProfile.FromSettings(
                SavedConnectionProfile.DisplayNameFor(settings, name),
                settings);
            Profiles.Add(existing);
        }
        else
        {
            existing.Name = SavedConnectionProfile.DisplayNameFor(settings, name);
            existing.Settings = settings.Clone();
        }

        existing.LastUsedUtc = DateTimeOffset.UtcNow;
        SelectedProfileId = existing.Id;
        return existing;
    }

    public void Normalize()
    {
        SchemaVersion = 2;
        Profiles.RemoveAll(profile =>
            profile.Settings is null ||
            string.IsNullOrWhiteSpace(profile.Settings.ServerEndpoint) ||
            string.IsNullOrWhiteSpace(profile.Settings.DeviceId));

        foreach (var profile in Profiles)
        {
            if (string.IsNullOrWhiteSpace(profile.Id))
            {
                profile.Id = Guid.NewGuid().ToString("N");
            }

            profile.Name = SavedConnectionProfile.DisplayNameFor(profile.Settings, profile.Name);
            profile.Settings = profile.Settings.Clone();
        }

        if (Profiles.Count == 0)
        {
            SelectedProfileId = "";
            return;
        }

        if (!Profiles.Any(profile => string.Equals(profile.Id, SelectedProfileId, StringComparison.Ordinal)))
        {
            SelectedProfileId = Profiles[0].Id;
        }
    }
}

public sealed class SavedConnectionProfile
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("settings")]
    public ConnectionSettings Settings { get; set; } = new();

    [JsonPropertyName("created_at_utc")]
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("last_used_utc")]
    public DateTimeOffset? LastUsedUtc { get; set; }

    public override string ToString()
    {
        return Name;
    }

    public static SavedConnectionProfile FromSettings(string name, ConnectionSettings settings, string? id = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        return new SavedConnectionProfile
        {
            Id = string.IsNullOrWhiteSpace(id) ? Guid.NewGuid().ToString("N") : id,
            Name = DisplayNameFor(settings, name),
            Settings = settings.Clone(),
        };
    }

    public static string DisplayNameFor(ConnectionSettings settings, string? requestedName = null)
    {
        if (!string.IsNullOrWhiteSpace(requestedName))
        {
            return requestedName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(settings.DeviceName))
        {
            return settings.DeviceName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(settings.ServerEndpoint))
        {
            return settings.ServerEndpoint.Trim();
        }

        return "Omega VPN";
    }
}
