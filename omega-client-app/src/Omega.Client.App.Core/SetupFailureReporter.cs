using System.Text;

namespace Omega.Client.App.Core;

public static class SetupFailureReporter
{
    public static void Trace(string logPath, string message, TextWriter? errorWriter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        errorWriter ??= Console.Error;

        var entry = $"[{DateTimeOffset.Now:O}] {message}";
        try
        {
            Append(logPath, entry + Environment.NewLine);
        }
        catch (Exception logException)
        {
            errorWriter.WriteLine($"Failed to write setup trace '{logPath}': {logException}");
        }
    }

    public static void Report(
        string logPath,
        string stage,
        Exception exception,
        TextWriter? errorWriter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        ArgumentNullException.ThrowIfNull(exception);

        errorWriter ??= Console.Error;
        var report = Format(stage, exception);
        errorWriter.WriteLine(report);

        try
        {
            var fullLogPath = Append(logPath, report + Environment.NewLine + Environment.NewLine);
            errorWriter.WriteLine($"Setup log: {fullLogPath}");
        }
        catch (Exception logException)
        {
            errorWriter.WriteLine($"Failed to write setup log '{logPath}': {logException}");
        }
    }

    public static string Format(string stage, Exception exception)
    {
        return $"[{DateTimeOffset.Now:O}] Omega VPN setup failed during {stage}.{Environment.NewLine}{exception}";
    }

    private static string Append(string logPath, string content)
    {
        var fullLogPath = Path.GetFullPath(logPath);
        var logDirectory = Path.GetDirectoryName(fullLogPath);
        if (!string.IsNullOrWhiteSpace(logDirectory))
        {
            Directory.CreateDirectory(logDirectory);
        }

        File.AppendAllText(
            fullLogPath,
            content,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return fullLogPath;
    }
}
