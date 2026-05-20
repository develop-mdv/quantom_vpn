using System.Text.RegularExpressions;

namespace Omega.Client.App.Core;

public sealed record ValidationIssue(string Field, string Message);

public static partial class ConnectionSettingsValidator
{
    public static IReadOnlyList<ValidationIssue> Validate(ConnectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var errors = new List<ValidationIssue>();
        if (string.IsNullOrWhiteSpace(settings.ServerEndpoint))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.ServerEndpoint), "Server endpoint is required."));
        }
        else if (!LooksLikeEndpoint(settings.ServerEndpoint))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.ServerEndpoint), "Use host:port or [ipv6]:port."));
        }

        if (string.IsNullOrWhiteSpace(settings.DeviceId))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.DeviceId), "Device id is required."));
        }
        else if (!Guid.TryParse(settings.DeviceId, out _))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.DeviceId), "Device id must be a UUID."));
        }

        if (string.IsNullOrWhiteSpace(settings.DeviceToken))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.DeviceToken), "Device token is required."));
        }
        else if (!DeviceTokenRegex().IsMatch(settings.DeviceToken.Trim()))
        {
            errors.Add(new ValidationIssue(nameof(ConnectionSettings.DeviceToken), "Device token must be 64 hex characters."));
        }

        // REALITY: только валидируем когда чекбокс "Включить обход" выставлен.
        // Один self-contained omega-reality://<base64url-json> код заменяет все
        // прежние поля (server / sni / pubkey / short_id / fingerprint).
        if (settings.RealityEnabled)
        {
            if (string.IsNullOrWhiteSpace(settings.RealityCode))
            {
                errors.Add(new ValidationIssue(nameof(ConnectionSettings.RealityCode),
                    "Вставьте REALITY-код из админки — без него обход не включится."));
            }
            else if (!IsValidRealityCode(settings.RealityCode))
            {
                errors.Add(new ValidationIssue(nameof(ConnectionSettings.RealityCode),
                    "REALITY-код некорректен. Скопируйте свежий код из админки заново."));
            }
        }

        return errors;
    }

    private static bool IsValidRealityCode(string code)
    {
        var trimmed = code.Trim();
        const string prefix = "omega-reality://";
        if (!trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var payload = trimmed.Substring(prefix.Length);
        try
        {
            var bytes = DecodeBase64Permissive(payload);
            var json = System.Text.Json.JsonDocument.Parse(System.Text.Encoding.UTF8.GetString(bytes));
            var root = json.RootElement;
            if (!root.TryGetProperty("server", out _)) return false;
            if (!root.TryGetProperty("sni", out _)) return false;
            if (!root.TryGetProperty("pubkey", out var pk)) return false;
            var pkStr = pk.GetString();
            if (string.IsNullOrWhiteSpace(pkStr)) return false;
            var pkBytes = Convert.FromBase64String(pkStr.Trim());
            return pkBytes.Length == 32;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] DecodeBase64Permissive(string s)
    {
        var v = s.Trim().Replace('-', '+').Replace('_', '/');
        switch (v.Length % 4)
        {
            case 2: v += "=="; break;
            case 3: v += "="; break;
        }
        return Convert.FromBase64String(v);
    }

    private static bool LooksLikeEndpoint(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var end = trimmed.LastIndexOf("]:", StringComparison.Ordinal);
            return end > 1 && int.TryParse(trimmed[(end + 2)..], out var port) && port > 0 && port <= 65535;
        }

        var separator = trimmed.LastIndexOf(':');
        return separator > 0
            && separator < trimmed.Length - 1
            && int.TryParse(trimmed[(separator + 1)..], out var parsedPort)
            && parsedPort > 0
            && parsedPort <= 65535;
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex DeviceTokenRegex();
}
