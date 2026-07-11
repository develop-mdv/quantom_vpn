namespace Omega.Client.App.Core;

public static class InstallDirectoryUpdater
{
    public static void Replace(
        string payloadDir,
        string installDir,
        Action<string>? log = null,
        bool preferAtomicSwap = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(installDir);

        payloadDir = Path.GetFullPath(payloadDir);
        installDir = Path.GetFullPath(installDir);
        var parentDirectory = Directory.GetParent(installDir)?.FullName
            ?? throw new InvalidOperationException("Installation directory cannot be a drive root.");
        Directory.CreateDirectory(parentDirectory);

        var directoryName = Path.GetFileName(installDir);
        var operationId = Guid.NewGuid().ToString("N");
        var stagingDir = Path.Combine(parentDirectory, $".{directoryName}.staging-{operationId}");
        var atomicBackupDir = Path.Combine(parentDirectory, $".{directoryName}.backup-{operationId}");

        try
        {
            Directory.CreateDirectory(stagingDir);
            CopyDirectory(payloadDir, stagingDir);
            ValidateStagedApp(stagingDir);
            File.WriteAllText(
                Path.Combine(stagingDir, ClientPaths.InstalledMarkerFileName),
                DateTimeOffset.UtcNow.ToString("O"));

            if (!Directory.Exists(installDir))
            {
                Directory.Move(stagingDir, installDir);
                return;
            }

            if (preferAtomicSwap && TryAtomicSwap(stagingDir, installDir, atomicBackupDir, log))
            {
                return;
            }

            log?.Invoke("Atomic directory swap is unavailable; using a backed-up in-place update.");
            ReplaceContentsWithBackup(stagingDir, installDir, operationId, log);
        }
        finally
        {
            TryDeleteDirectory(stagingDir, log);
        }
    }

    private static bool TryAtomicSwap(
        string stagingDir,
        string installDir,
        string backupDir,
        Action<string>? log)
    {
        try
        {
            Directory.Move(installDir, backupDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log?.Invoke($"Atomic directory swap was denied: {ex.Message}");
            return false;
        }

        try
        {
            Directory.Move(stagingDir, installDir);
        }
        catch
        {
            if (!Directory.Exists(installDir) && Directory.Exists(backupDir))
            {
                Directory.Move(backupDir, installDir);
            }

            throw;
        }

        TryDeleteDirectory(backupDir, log);
        return true;
    }

    private static void ReplaceContentsWithBackup(
        string stagingDir,
        string installDir,
        string operationId,
        Action<string>? log)
    {
        var backupDir = Path.Combine(Path.GetTempPath(), $"OmegaVPN-setup-backup-{operationId}");
        var installationModified = false;
        var updateSucceeded = false;
        var restoreSucceeded = false;

        try
        {
            Directory.CreateDirectory(backupDir);
            CopyDirectory(installDir, backupDir);

            installationModified = true;
            ClearDirectoryContents(installDir);
            CopyDirectory(stagingDir, installDir);
            ValidateStagedApp(installDir);
            updateSucceeded = true;
        }
        catch (Exception updateException)
        {
            if (!installationModified)
            {
                throw;
            }

            try
            {
                Directory.CreateDirectory(installDir);
                CopyDirectory(backupDir, installDir);
                restoreSucceeded = true;
            }
            catch (Exception restoreException)
            {
                throw new AggregateException(
                    $"In-place update failed and the previous installation could not be fully restored. Backup: {backupDir}",
                    updateException,
                    restoreException);
            }

            throw new IOException("In-place update failed; the previous installation was restored.", updateException);
        }
        finally
        {
            if (!installationModified || updateSucceeded || restoreSucceeded)
            {
                TryDeleteDirectory(backupDir, log);
            }
        }
    }

    private static void ClearDirectoryContents(string directory)
    {
        foreach (var file in Directory.GetFiles(directory))
        {
            File.SetAttributes(file, FileAttributes.Normal);
            File.Delete(file);
        }

        foreach (var childDirectory in Directory.GetDirectories(directory))
        {
            NormalizeFileAttributes(childDirectory);
            Directory.Delete(childDirectory, recursive: true);
        }
    }

    private static void NormalizeFileAttributes(string directory)
    {
        foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
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

    private static void ValidateStagedApp(string directory)
    {
        var appPath = Path.Combine(directory, "Omega.Client.App.exe");
        if (!File.Exists(appPath))
        {
            throw new InvalidOperationException($"Installer payload is missing {Path.GetFileName(appPath)}.");
        }
    }

    private static void TryDeleteDirectory(string directory, Action<string>? log)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        try
        {
            NormalizeFileAttributes(directory);
            Directory.Delete(directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log?.Invoke($"Temporary directory could not be removed: {directory}. {ex.Message}");
        }
    }
}
