using System.Diagnostics;

namespace Omega.Client.App.Core;

public static class AutostartTask
{
    public static string[] BuildCreateArguments(string appPath)
    {
        return
        [
            "/Create",
            "/TN", "Omega VPN",
            "/SC", "ONLOGON",
            "/TR", $"\"{appPath}\"",
            "/RL", "HIGHEST",
            "/F",
        ];
    }

    public static string[] BuildDeleteArguments()
    {
        return
        [
            "/Delete",
            "/TN", "Omega VPN",
            "/F",
        ];
    }

    public static void Apply(bool enabled, ClientPaths paths)
    {
        var args = enabled
            ? BuildCreateArguments(Path.Combine(paths.RootPath, "Omega.Client.App.exe"))
            : BuildDeleteArguments();

        var startInfo = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = Process.Start(startInfo);
        process?.WaitForExit();
    }
}
