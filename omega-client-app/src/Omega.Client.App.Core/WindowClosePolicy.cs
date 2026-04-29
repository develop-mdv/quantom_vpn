namespace Omega.Client.App.Core;

public enum WindowCloseAction
{
    ExitApplication,
    HideToTray,
}

public static class WindowClosePolicy
{
    public static WindowCloseAction Decide(bool hasActiveRuntime, bool explicitExitRequested)
    {
        if (hasActiveRuntime && !explicitExitRequested)
        {
            return WindowCloseAction.HideToTray;
        }

        return WindowCloseAction.ExitApplication;
    }
}
