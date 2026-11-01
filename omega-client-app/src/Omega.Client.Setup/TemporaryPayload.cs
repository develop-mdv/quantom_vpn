sealed class TemporaryPayload(string path) : IDisposable
{
    public string Path { get; } = System.IO.Path.GetFullPath(path);

    public void Dispose()
    {
        var parent = System.IO.Path.GetFullPath(System.IO.Path.GetTempPath()).TrimEnd(System.IO.Path.DirectorySeparatorChar);
        if (!string.Equals(System.IO.Path.GetDirectoryName(Path), parent, StringComparison.OrdinalIgnoreCase) ||
            !System.IO.Path.GetFileName(Path).StartsWith("OmegaVPN-setup-", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected setup temporary directory.");
        try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
        catch (IOException) { Console.Error.WriteLine("Could not remove the temporary setup directory: " + Path); }
        catch (UnauthorizedAccessException) { Console.Error.WriteLine("Could not remove the temporary setup directory: " + Path); }
    }
}
