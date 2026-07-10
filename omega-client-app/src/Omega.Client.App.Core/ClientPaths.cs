namespace Omega.Client.App.Core;

public sealed class ClientPaths
{
    public const string InstalledMarkerFileName = ".omega-vpn-installed";

    private ClientPaths(string rootPath, string stateDirectory, string? legacyConfigPath)
    {
        RootPath = Path.GetFullPath(rootPath);
        RuntimeExePath = Path.Combine(RootPath, "omega-client.exe");
        WintunPath = Path.Combine(RootPath, "wintun.dll");
        StateDirectory = Path.GetFullPath(stateDirectory);
        ConfigPath = Path.Combine(StateDirectory, "app-config.json");
        LegacyConfigPath = legacyConfigPath is null ? null : Path.GetFullPath(legacyConfigPath);
        DiagnosticsPath = Path.Combine(StateDirectory, "diagnostics.json");
        LifecyclePath = Path.Combine(StateDirectory, "lifecycle.json");
        ControlPath = Path.Combine(StateDirectory, "runtime-control.json");
        PidPath = Path.Combine(StateDirectory, "runtime.pid");
        LogPath = Path.Combine(StateDirectory, "runtime.log");
    }

    public string RootPath { get; }
    public string RuntimeExePath { get; }
    public string WintunPath { get; }
    public string StateDirectory { get; }
    public string ConfigPath { get; }
    public string? LegacyConfigPath { get; }
    public string DiagnosticsPath { get; }
    public string LifecyclePath { get; }
    public string ControlPath { get; }
    public string PidPath { get; }
    public string LogPath { get; }

    public static ClientPaths ForPortableRoot(string rootPath)
    {
        var fullRoot = Path.GetFullPath(rootPath);
        return new ClientPaths(
            fullRoot,
            Path.Combine(fullRoot, "omega-client", "state"),
            legacyConfigPath: null);
    }

    public static ClientPaths ForInstalledRoot(string rootPath, string localApplicationData)
    {
        var fullRoot = Path.GetFullPath(rootPath);
        return new ClientPaths(
            fullRoot,
            Path.Combine(localApplicationData, "Omega VPN", "state"),
            Path.Combine(fullRoot, "omega-client", "state", "app-config.json"));
    }

    public static ClientPaths ForCurrentApp()
    {
        var baseDirectory = AppContext.BaseDirectory;
        var installedMarker = Path.Combine(baseDirectory, InstalledMarkerFileName);
        if (File.Exists(installedMarker))
        {
            var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return ForInstalledRoot(baseDirectory, localApplicationData);
        }

        return ForPortableRoot(baseDirectory);
    }
}
