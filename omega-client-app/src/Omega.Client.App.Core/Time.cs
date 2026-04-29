namespace Omega.Client.App.Core;

internal static class Time
{
    public static long NowMs()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
