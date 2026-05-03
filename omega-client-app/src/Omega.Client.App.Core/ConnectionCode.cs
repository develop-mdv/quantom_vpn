using System.Text;
using System.Text.Json;

namespace Omega.Client.App.Core;

public sealed record ConnectionCodeParseResult(
    bool Success,
    ConnectionSettings? Settings,
    string ProfileName,
    string? ErrorMessage)
{
    public static ConnectionCodeParseResult Ok(ConnectionSettings settings, string profileName)
    {
        return new ConnectionCodeParseResult(true, settings, profileName, null);
    }

    public static ConnectionCodeParseResult Fail(string message)
    {
        return new ConnectionCodeParseResult(false, null, "", message);
    }
}

public static class ConnectionCode
{
    public static string Create(ConnectionSettings settings, string? profileName = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var payload = new Dictionary<string, string>
        {
            ["name"] = SavedConnectionProfile.DisplayNameFor(settings, profileName),
            ["server"] = settings.ServerEndpoint,
            ["device_id"] = settings.DeviceId,
            ["token"] = settings.DeviceToken,
            ["device_name"] = settings.DeviceName,
            ["transport"] = settings.Transport,
        };
        var json = JsonSerializer.Serialize(payload, JsonOptions.Default);
        return "omega://connect/" + Base64UrlEncode(Encoding.UTF8.GetBytes(json));
    }

    internal static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public static class ConnectionCodeParser
{
    public static ConnectionCodeParseResult Parse(string code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return ConnectionCodeParseResult.Fail("Введите код подключения.");
        }

        var trimmed = code.Trim();
        ConnectionCodeParseResult result;
        if (trimmed.Contains("OMEGA_", StringComparison.OrdinalIgnoreCase))
        {
            result = ParseEnv(trimmed);
        }
        else if (trimmed.StartsWith("{", StringComparison.Ordinal))
        {
            result = ParseJson(trimmed);
        }
        else
        {
            result = ParseCompact(trimmed);
        }

        if (!result.Success || result.Settings is null)
        {
            return result;
        }

        var errors = ConnectionSettingsValidator.Validate(result.Settings);
        if (errors.Count > 0)
        {
            return ConnectionCodeParseResult.Fail(errors[0].Message);
        }

        return result;
    }

    private static ConnectionCodeParseResult ParseCompact(string value)
    {
        var payload = value;
        const string urlPrefix = "omega://connect/";
        const string shortPrefix = "omega:";

        if (payload.StartsWith(urlPrefix, StringComparison.OrdinalIgnoreCase))
        {
            payload = payload[urlPrefix.Length..];
        }
        else if (payload.StartsWith(shortPrefix, StringComparison.OrdinalIgnoreCase))
        {
            payload = payload[shortPrefix.Length..];
        }

        var separator = payload.IndexOfAny(['?', '#']);
        if (separator >= 0)
        {
            payload = payload[..separator];
        }

        try
        {
            var json = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            return ParseJson(json);
        }
        catch (FormatException)
        {
            return ConnectionCodeParseResult.Fail("Код подключения не распознан.");
        }
        catch (JsonException)
        {
            return ConnectionCodeParseResult.Fail("Код подключения поврежден.");
        }
    }

    private static ConnectionCodeParseResult ParseJson(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return ConnectionCodeParseResult.Fail("Код подключения должен содержать объект настроек.");
        }

        var settings = new ConnectionSettings
        {
            ServerEndpoint = FirstString(root, "server", "server_endpoint", "omega_server"),
            DeviceId = FirstString(root, "device_id", "id", "omega_device_id"),
            DeviceToken = FirstString(root, "token", "device_token", "omega_device_token"),
            DeviceName = FirstStringOr(root, Environment.MachineName, "device_name", "name", "omega_device_name"),
            Transport = FirstStringOr(root, "auto", "transport", "omega_transport"),
            Profile = FirstStringOr(root, "gaming", "profile", "omega_profile"),
            TunnelMode = FirstStringOr(root, "full", "tunnel_mode", "omega_tunnel_mode"),
            MtuPolicy = FirstStringOr(root, "auto", "mtu_policy", "omega_mtu_policy"),
            DnsPolicy = FirstStringOr(root, "tunnel", "dns_policy", "omega_dns_policy"),
            DnsServers = FirstStringOr(root, "1.1.1.1,8.8.8.8", "dns_servers", "omega_dns_servers"),
            Ipv6Policy = FirstStringOr(root, "tunnel", "ipv6_policy", "omega_ipv6_policy"),
            KillSwitch = FirstStringOr(root, "soft", "kill_switch", "omega_kill_switch"),
            DnsLeakGuard = FirstStringOr(root, "warn", "dns_leak_guard", "omega_dns_leak_guard"),
            NetworkDiagnostics = true,
        };
        var profileName = FirstString(root, "profile_name", "connection_name", "name");
        return ConnectionCodeParseResult.Ok(settings, SavedConnectionProfile.DisplayNameFor(settings, profileName));
    }

    private static ConnectionCodeParseResult ParseEnv(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var index = line.IndexOf('=');
            if (index <= 0)
            {
                continue;
            }

            var key = line[..index].Trim();
            var value = line[(index + 1)..].Trim().Trim('"', '\'');
            values[key] = value;
        }

        var settings = new ConnectionSettings
        {
            ServerEndpoint = Env(values, "OMEGA_SERVER"),
            DeviceId = Env(values, "OMEGA_DEVICE_ID"),
            DeviceToken = Env(values, "OMEGA_DEVICE_TOKEN"),
            DeviceName = Env(values, "OMEGA_DEVICE_NAME", Environment.MachineName),
            Transport = Env(values, "OMEGA_TRANSPORT", "auto"),
            Profile = Env(values, "OMEGA_PROFILE", "gaming"),
            TunnelMode = Env(values, "OMEGA_TUNNEL_MODE", "full"),
            MtuPolicy = Env(values, "OMEGA_MTU_POLICY", "auto"),
            DnsPolicy = Env(values, "OMEGA_DNS_POLICY", "tunnel"),
            DnsServers = Env(values, "OMEGA_DNS_SERVERS", "1.1.1.1,8.8.8.8"),
            Ipv6Policy = Env(values, "OMEGA_IPV6_POLICY", "tunnel"),
            KillSwitch = Env(values, "OMEGA_KILL_SWITCH", "soft"),
            DnsLeakGuard = Env(values, "OMEGA_DNS_LEAK_GUARD", "warn"),
            NetworkDiagnostics = true,
        };
        return ConnectionCodeParseResult.Ok(settings, SavedConnectionProfile.DisplayNameFor(settings));
    }

    private static string FirstString(JsonElement root, params string[] names)
    {
        return FirstStringOr(root, "", names);
    }

    private static string FirstStringOr(JsonElement root, string fallback, params string[] names)
    {
        foreach (var name in names)
        {
            if (TryGetPropertyIgnoreCase(root, name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString()?.Trim() ?? "";
            }
        }

        return fallback;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement root, string name, out JsonElement value)
    {
        foreach (var property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static string Env(IReadOnlyDictionary<string, string> values, string name, string fallback = "")
    {
        return values.TryGetValue(name, out var value) ? value.Trim() : fallback;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }

        return Convert.FromBase64String(padded);
    }
}
