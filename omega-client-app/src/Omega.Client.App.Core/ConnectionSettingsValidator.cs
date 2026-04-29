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

        return errors;
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
