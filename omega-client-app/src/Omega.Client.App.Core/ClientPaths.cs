namespace Omega.Client.App.Core;

public sealed class ClientPaths
{
    private ClientPaths(string rootPath)
    {
        RootPath = Path.GetFullPath(rootPath);
        RuntimeExePath = Path.Combine(RootPath, "omega-client.exe");
        WintunPath = Path.Combine(RootPath, "wintun.dll");
        StateDirectory = Path.Combine(RootPath, "omega-client", "state");
        ConfigPath = Path.Combine(StateDirectory, "app-config.json");
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
    public string DiagnosticsPath { get; }
    public string LifecyclePath { get; }
    public string ControlPath { get; }
    public string PidPath { get; }
    public string LogPath { get; }

    public static ClientPaths ForPortableRoot(string rootPath) => new(rootPath);

    public static ClientPaths ForCurrentApp()
    {
        var baseDirectory = AppContext.BaseDirectory;
        return new ClientPaths(baseDirectory);
    }
}
