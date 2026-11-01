using System.IO.Compression;

namespace Omega.Client.App.Core;

public static class InstallerPayloadArchive
{
    public static int Validate(Stream stream)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        return ValidateEntries(archive);
    }

    public static void Extract(Stream stream, string destination)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        ValidateEntries(archive);
        archive.ExtractToDirectory(destination);
    }

    private static int ValidateEntries(ZipArchive archive)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalSize = 0;
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            var parts = name.Split('/');
            if (name.StartsWith('/') || name.Contains(':') || parts.Any(part => part is ".." or "."))
                throw new InvalidDataException("Unsafe installer payload path.");
            var fileName = parts.Last();
            if (parts.Any(part => part.Equals("state", StringComparison.OrdinalIgnoreCase)) ||
                fileName.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("app-config", StringComparison.OrdinalIgnoreCase) && fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Installer payload contains private client state.");
            if (!names.Add(name))
                throw new InvalidDataException("Duplicate installer payload path.");
            totalSize = checked(totalSize + entry.Length);
            if (totalSize > 1024L * 1024 * 1024)
                throw new InvalidDataException("Installer payload is too large.");
        }
        foreach (var required in new[] { "Omega.Client.App.exe", "omega-client.exe", "wintun.dll", "hostfxr.dll", "coreclr.dll" })
            if (!names.Contains(required))
                throw new InvalidDataException($"Installer payload is missing {required}.");
        return archive.Entries.Count;
    }
}
