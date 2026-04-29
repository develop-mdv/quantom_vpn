using System.Diagnostics;
using System.Security.Principal;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

var command = args.FirstOrDefault(arg => !arg.StartsWith("--", StringComparison.OrdinalIgnoreCase)) ?? "install";
var installDir = ReadOption(args, "--target") ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
    "Omega VPN");
var autostart = !args.Contains("--no-autostart", StringComparer.OrdinalIgnoreCase);

if (!IsAdministrator())
{
    RelaunchElevated(args);
    return;
}

if (string.Equals(command, "uninstall", StringComparison.OrdinalIgnoreCase))
{
    Uninstall(installDir);
    return;
}

Install(installDir, autostart);

static void Install(string installDir, bool autostart)
{
    var baseDir = AppContext.BaseDirectory;
    var payloadDir = Path.Combine(baseDir, "payload");
    if (!Directory.Exists(payloadDir))
    {
        Console.Error.WriteLine($"Payload directory not found: {payloadDir}");
        Environment.ExitCode = 1;
        return;
    }

    Console.WriteLine($"Installing Omega VPN to {installDir}");
    Directory.CreateDirectory(installDir);
    CopyDirectory(payloadDir, installDir);

    var appPath = Path.Combine(installDir, "Omega.Client.App.exe");
    if (!File.Exists(appPath))
    {
        Console.Error.WriteLine($"Installed app not found: {appPath}");
        Environment.ExitCode = 1;
        return;
    }

    CreateShortcuts(appPath, installDir);
    if (autostart)
    {
        ConfigureAutostart(appPath, enabled: true);
    }

    Console.WriteLine("Omega VPN installed.");
}

static void Uninstall(string installDir)
{
    Console.WriteLine("Uninstalling Omega VPN");
    ConfigureAutostart("", enabled: false);
    DeleteShortcut(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Omega VPN.lnk");
    DeleteShortcut(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Omega VPN"),
        "Omega VPN.lnk");

    if (Directory.Exists(installDir))
    {
        Directory.Delete(installDir, recursive: true);
    }

    Console.WriteLine("Omega VPN removed.");
}

static string? ReadOption(string[] args, string name)
{
    for (var i = 0; i < args.Length; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
        {
            return args[i + 1];
        }
    }

    return null;
}

static bool IsAdministrator()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

static void RelaunchElevated(string[] args)
{
    var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
    if (string.IsNullOrWhiteSpace(exePath))
    {
        Console.Error.WriteLine("Cannot determine setup executable path.");
        Environment.ExitCode = 1;
        return;
    }

    var startInfo = new ProcessStartInfo
    {
        FileName = exePath,
        UseShellExecute = true,
        Verb = "runas",
    };
    foreach (var arg in args)
    {
        startInfo.ArgumentList.Add(arg);
    }

    Process.Start(startInfo);
}

static void CopyDirectory(string sourceDir, string targetDir)
{
    foreach (var directory in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
    {
        var target = Path.Combine(targetDir, Path.GetRelativePath(sourceDir, directory));
        Directory.CreateDirectory(target);
    }

    foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
    {
        var target = Path.Combine(targetDir, Path.GetRelativePath(sourceDir, file));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Copy(file, target, overwrite: true);
    }
}

static void CreateShortcuts(string appPath, string workingDirectory)
{
    CreateShortcut(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Omega VPN.lnk"),
        appPath,
        workingDirectory);

    var startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Omega VPN");
    Directory.CreateDirectory(startMenuDir);
    CreateShortcut(Path.Combine(startMenuDir, "Omega VPN.lnk"), appPath, workingDirectory);
}

static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory)
{
    var shellType = Type.GetTypeFromProgID("WScript.Shell");
    if (shellType is null)
    {
        Console.WriteLine("WScript.Shell is not available; shortcut skipped.");
        return;
    }

    dynamic shell = Activator.CreateInstance(shellType)!;
    dynamic shortcut = shell.CreateShortcut(shortcutPath);
    shortcut.TargetPath = targetPath;
    shortcut.WorkingDirectory = workingDirectory;
    shortcut.Description = "Omega VPN";
    shortcut.Save();
}

static void DeleteShortcut(string directory, string fileName)
{
    var path = Path.Combine(directory, fileName);
    if (File.Exists(path))
    {
        File.Delete(path);
    }
}

static void ConfigureAutostart(string appPath, bool enabled)
{
    var args = enabled
        ? new[]
        {
            "/Create",
            "/TN", "Omega VPN",
            "/SC", "ONLOGON",
            "/TR", $"\"{appPath}\"",
            "/RL", "HIGHEST",
            "/F",
        }
        : new[]
        {
            "/Delete",
            "/TN", "Omega VPN",
            "/F",
        };

    var startInfo = new ProcessStartInfo
    {
        FileName = "schtasks.exe",
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    foreach (var arg in args)
    {
        startInfo.ArgumentList.Add(arg);
    }

    using var process = Process.Start(startInfo);
    process?.WaitForExit();
}
