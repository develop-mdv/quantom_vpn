using Omega.Client.App.Core;

namespace Omega.Client.App;

public partial class App : System.Windows.Application
{
    private ClientInstanceCoordinator? instanceCoordinator;

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);
        instanceCoordinator = ClientInstanceCoordinator.Create(HandleInstanceCommand);
        if (!instanceCoordinator.IsPrimary)
        {
            instanceCoordinator.SendToPrimary(ClientInstanceCommand.Activate, TimeSpan.FromSeconds(5));
            instanceCoordinator.Dispose();
            instanceCoordinator = null;
            Shutdown();
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        instanceCoordinator?.Dispose();
        instanceCoordinator = null;
        base.OnExit(e);
    }

    private void HandleInstanceCommand(ClientInstanceCommand command)
    {
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
        {
            return;
        }

        Dispatcher.BeginInvoke(() => HandleInstanceCommandOnUiThread(command));
    }

    private async void HandleInstanceCommandOnUiThread(ClientInstanceCommand command)
    {
        if (MainWindow is not MainWindow window)
        {
            return;
        }

        switch (command)
        {
            case ClientInstanceCommand.Activate:
                window.BringToFront();
                break;
            case ClientInstanceCommand.ExitForUpdate:
                await window.ExitApplicationAsync();
                break;
        }
    }
}
