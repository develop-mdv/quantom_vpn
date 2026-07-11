using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using Omega.Client.App.Core;

Console.OutputEncoding = Encoding.UTF8;

var command = args.Contains("uninstall", StringComparer.OrdinalIgnoreCase) ? "uninstall" : "install";
var installDir = ReadOption(args, "--target") ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
    "Omega VPN");
var autostart = !args.Contains("--no-autostart", StringComparer.OrdinalIgnoreCase);
var setupLogPath = ReadOption(args, "--log")
    ?? Path.Combine(AppContext.BaseDirectory, "OmegaVPN-setup.log");
var isAdministrator = IsAdministrator();

SetupFailureReporter.Trace(
    setupLogPath,
    $"Setup started. Command={command}; Elevated={isAdministrator}; User={Environment.UserName}; BaseDir={AppContext.BaseDirectory}; InstallDir={installDir}");

if (!isAdministrator)
{
    try
    {
        Environment.ExitCode = RelaunchElevated(args);
    }
    catch (Exception ex)
    {
        SetupFailureReporter.Report(setupLogPath, "elevation", ex);
        Environment.ExitCode = 1;
    }
    return;
}

try
{
    if (string.Equals(command, "uninstall", StringComparison.OrdinalIgnoreCase))
    {
        Uninstall(installDir);
        return;
    }

    Install(installDir, autostart);
}
catch (Exception ex)
{
    SetupFailureReporter.Report(setupLogPath, command, ex);
    Environment.ExitCode = 1;
}

static void Install(string installDir, bool autostart)
{
    var baseDir = AppContext.BaseDirectory;
    var payloadDir = Path.Combine(baseDir, "payload");
    if (!Directory.Exists(payloadDir))
    {
        throw new DirectoryNotFoundException($"Payload directory not found: {payloadDir}");
    }

    var bundledConfig = Directory
        .EnumerateFiles(payloadDir, "app-config*.json", SearchOption.AllDirectories)
        .FirstOrDefault();
    if (bundledConfig is not null)
    {
        throw new InvalidOperationException("Installer payload contains a user app-config.json and is unsafe to install.");
    }

    Console.WriteLine($"Installing Omega VPN to {installDir}");
    StopInstalledClient(installDir);
    EnsureNoOtherClientProcesses();
    MigrateLegacyConfig(installDir);
    ReplaceInstallDirectory(payloadDir, installDir);

    var appPath = Path.Combine(installDir, "Omega.Client.App.exe");
    if (!File.Exists(appPath))
    {
        throw new FileNotFoundException($"Installed app not found: {appPath}", appPath);
    }

    CreateShortcuts(appPath, installDir);
    ConfigureAutostart(appPath, enabled: autostart);

    Console.WriteLine("Omega VPN installed.");
}

static void Uninstall(string installDir)
{
    Console.WriteLine("Uninstalling Omega VPN");
    StopInstalledClient(installDir);
    EnsureNoOtherClientProcesses();
    MigrateLegacyConfig(installDir);
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

static void StopInstalledClient(string installDir)
{
    var appPath = Path.GetFullPath(Path.Combine(installDir, "Omega.Client.App.exe"));
    var runtimePath = Path.GetFullPath(Path.Combine(installDir, "omega-client.exe"));
    var processes = FindProcessesAtPaths(appPath, runtimePath);
    try
    {
        if (processes.Count == 0)
        {
            return;
        }

        var appProcess = processes.FirstOrDefault(process => ProcessPathEquals(process, appPath));
        if (appProcess is not null)
        {
            Console.WriteLine("Stopping the running Omega VPN client before update...");
            if (!ClientInstanceCoordinator.SendToPrimaryInstance(
                    ClientInstanceCommand.ExitForUpdate,
                    TimeSpan.FromSeconds(5)))
            {
                throw new InvalidOperationException(
                    "Omega VPN is running. Exit it from the system tray, then run setup again.");
            }

            if (!appProcess.WaitForExit((int)TimeSpan.FromSeconds(30).TotalMilliseconds))
            {
                throw new InvalidOperationException(
                    "Omega VPN did not stop in time. Exit it from the system tray, then run setup again.");
            }
        }

        foreach (var process in FindProcessesAtPaths(appPath, runtimePath))
        {
            process.Dispose();
            throw new InvalidOperationException(
                "An Omega VPN process is still using the installation directory. Close it and run setup again.");
        }
    }
    finally
    {
        foreach (var process in processes)
        {
            process.Dispose();
        }
    }
}

static void EnsureNoOtherClientProcesses()
{
    var running = new List<Process>();
    try
    {
        foreach (var processName in new[] { "Omega.Client.App", "omega-client" })
        {
            running.AddRange(Process.GetProcessesByName(processName));
        }

        if (running.Count > 0)
        {
            throw new InvalidOperationException(
                "Another Omega VPN or portable client is still running. Exit every Omega VPN instance from the system tray, then run setup again.");
        }
    }
    finally
    {
        foreach (var process in running)
        {
            process.Dispose();
        }
    }
}

static List<Process> FindProcessesAtPaths(params string[] expectedPaths)
{
    var expected = expectedPaths
        .Select(Path.GetFullPath)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);
    var result = new List<Process>();
    foreach (var processName in new[] { "Omega.Client.App", "omega-client" })
    {
        foreach (var process in Process.GetProcessesByName(processName))
        {
            if (expected.Any(path => ProcessPathEquals(process, path)))
            {
                result.Add(process);
            }
            else
            {
                process.Dispose();
            }
        }
    }

    return result;
}

static bool ProcessPathEquals(Process process, string expectedPath)
{
    try
    {
        var actualPath = process.MainModule?.FileName;
        return actualPath is not null
            && string.Equals(Path.GetFullPath(actualPath), expectedPath, StringComparison.OrdinalIgnoreCase);
    }
    catch (InvalidOperationException)
    {
        return false;
    }
    catch (System.ComponentModel.Win32Exception)
    {
        return false;
    }
}

static void MigrateLegacyConfig(string installDir)
{
    var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    var paths = ClientPaths.ForInstalledRoot(installDir, localApplicationData);
    if (File.Exists(paths.ConfigPath)
        || string.IsNullOrWhiteSpace(paths.LegacyConfigPath)
        || !File.Exists(paths.LegacyConfigPath))
    {
        return;
    }

    Console.WriteLine($"Preserving connection profiles in {paths.StateDirectory}");
    Directory.CreateDirectory(paths.StateDirectory);
    File.Copy(paths.LegacyConfigPath, paths.ConfigPath, overwrite: false);
}

static void ReplaceInstallDirectory(string payloadDir, string installDir)
{
    installDir = Path.GetFullPath(installDir);
    var parentDirectory = Directory.GetParent(installDir)?.FullName
        ?? throw new InvalidOperationException("Installation directory cannot be a drive root.");
    Directory.CreateDirectory(parentDirectory);

    var directoryName = Path.GetFileName(installDir);
    var operationId = Guid.NewGuid().ToString("N");
    var stagingDir = Path.Combine(parentDirectory, $".{directoryName}.staging-{operationId}");
    var backupDir = Path.Combine(parentDirectory, $".{directoryName}.backup-{operationId}");
    var previousInstallMoved = false;

    try
    {
        Directory.CreateDirectory(stagingDir);
        CopyDirectory(payloadDir, stagingDir);
        var stagedApp = Path.Combine(stagingDir, "Omega.Client.App.exe");
        if (!File.Exists(stagedApp))
        {
            throw new InvalidOperationException($"Installer payload is missing {Path.GetFileName(stagedApp)}.");
        }

        File.WriteAllText(
            Path.Combine(stagingDir, ClientPaths.InstalledMarkerFileName),
            DateTimeOffset.UtcNow.ToString("O"));

        if (Directory.Exists(installDir))
        {
            Directory.Move(installDir, backupDir);
            previousInstallMoved = true;
        }

        try
        {
            Directory.Move(stagingDir, installDir);
        }
        catch
        {
            if (previousInstallMoved && !Directory.Exists(installDir) && Directory.Exists(backupDir))
            {
                Directory.Move(backupDir, installDir);
                previousInstallMoved = false;
            }

            throw;
        }
    }
    finally
    {
        if (Directory.Exists(stagingDir))
        {
            Directory.Delete(stagingDir, recursive: true);
        }
    }

    if (previousInstallMoved && Directory.Exists(backupDir))
    {
        try
        {
            Directory.Delete(backupDir, recursive: true);
        }
        catch (IOException ex)
        {
            Console.WriteLine($"Old installation backup could not be removed: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"Old installation backup could not be removed: {ex.Message}");
        }
    }
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

static int RelaunchElevated(string[] args)
{
    var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
    if (string.IsNullOrWhiteSpace(exePath))
    {
        throw new InvalidOperationException("Cannot determine setup executable path.");
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

    using var process = Process.Start(startInfo);
    if (process is null)
    {
        throw new InvalidOperationException("Failed to start elevated Omega VPN setup.");
    }

    process.WaitForExit();
    return process.ExitCode;
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
