using System.Diagnostics;

namespace Omega.Client.App.Core;

public static class RuntimeLaunchPlan
{
    public static ProcessStartInfo Create(ConnectionSettings settings, ClientPaths paths)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = paths.RuntimeExePath,
            WorkingDirectory = paths.RootPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var item in OmegaEnvironmentBuilder.Build(settings, paths))
        {
            startInfo.Environment[item.Key] = item.Value;
        }

        return startInfo;
    }
}
