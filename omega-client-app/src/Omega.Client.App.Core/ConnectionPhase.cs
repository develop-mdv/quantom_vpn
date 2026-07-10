namespace Omega.Client.App.Core;

public enum ConnectionPhase
{
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

public enum ConnectClickAction
{
    None,
    Connect,
    Disconnect,
}

public static class ConnectionPhasePolicy
{
    public static ConnectClickAction DecideClick(ConnectionPhase phase)
    {
        return phase switch
        {
            ConnectionPhase.Disconnected => ConnectClickAction.Connect,
            ConnectionPhase.Connected => ConnectClickAction.Disconnect,
            _ => ConnectClickAction.None,
        };
    }

    public static bool IsToggleEnabled(ConnectionPhase phase)
    {
        return phase is ConnectionPhase.Disconnected or ConnectionPhase.Connected;
    }

    public static string ToggleText(ConnectionPhase phase)
    {
        return phase switch
        {
            ConnectionPhase.Connecting => "Подключение…",
            ConnectionPhase.Connected => "Отключить",
            ConnectionPhase.Disconnecting => "Отключение…",
            _ => "Подключить",
        };
    }
}
