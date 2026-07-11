using System.Text;

namespace Omega.Client.App.Core;

public static class SetupFailureReporter
{
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
            var fullLogPath = Path.GetFullPath(logPath);
            var logDirectory = Path.GetDirectoryName(fullLogPath);
            if (!string.IsNullOrWhiteSpace(logDirectory))
            {
                Directory.CreateDirectory(logDirectory);
            }

            File.AppendAllText(
                fullLogPath,
                report + Environment.NewLine + Environment.NewLine,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
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
}
