using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Forms = System.Windows.Forms;
using Omega.Client.App.Core;

namespace Omega.Client.App;

public partial class MainWindow : Window
{
    private readonly ClientPaths paths;
    private readonly ConfigStore configStore;
    private readonly LifecycleStore lifecycleStore;
    private readonly DispatcherTimer diagnosticsTimer;
    private Forms.NotifyIcon? trayIcon;
    private Process? runtimeProcess;
    private StreamWriter? logWriter;
    private bool disconnectRequested;
    private bool explicitExitRequested;

    public MainWindow()
    {
        InitializeComponent();
        paths = ClientPaths.ForCurrentApp();
        configStore = new ConfigStore(paths);
        lifecycleStore = new LifecycleStore(paths);
        diagnosticsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        diagnosticsTimer.Tick += (_, _) => RefreshDiagnostics();

        LoadSettings();
        ConfigureTray();
        FooterText.Text = $"Журнал: {paths.LogPath}";
        diagnosticsTimer.Start();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        var hasActiveRuntime = runtimeProcess is { HasExited: false };
        if (WindowClosePolicy.Decide(hasActiveRuntime, explicitExitRequested) == WindowCloseAction.HideToTray)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        RequestRuntimeStopOnExit();
        diagnosticsTimer.Stop();
        trayIcon?.Dispose();
        logWriter?.Dispose();
        base.OnClosed(e);
        System.Windows.Application.Current.Shutdown();
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (runtimeProcess is { HasExited: false })
        {
            await DisconnectAsync();
            return;
        }

        await ConnectAsync();
    }

    private async Task ConnectAsync()
    {
        var settings = ReadSettings();
        var validation = ConnectionSettingsValidator.Validate(settings);
        if (validation.Count > 0)
        {
            SetStatus(ConnectionDisplayState.Error, "Проверьте данные", validation[0].Message);
            return;
        }

        configStore.Save(settings);
        try
        {
            AutostartTask.Apply(settings.Autostart, paths);
        }
        catch (Exception ex)
        {
            SetStatus(ConnectionDisplayState.Degraded, "Автозапуск не обновлен", ex.Message);
        }

        if (!File.Exists(paths.RuntimeExePath))
        {
            SetStatus(ConnectionDisplayState.Error, "Не найден omega-client.exe", paths.RuntimeExePath);
            return;
        }

        if (!File.Exists(paths.WintunPath))
        {
            SetStatus(ConnectionDisplayState.Error, "Не найден wintun.dll", paths.WintunPath);
            return;
        }

        Directory.CreateDirectory(paths.StateDirectory);
        if (File.Exists(paths.ControlPath))
        {
            File.Delete(paths.ControlPath);
        }

        disconnectRequested = false;
        lifecycleStore.Write(new LifecycleSnapshot
        {
            State = "connecting",
            ServerEndpoint = settings.ServerEndpoint,
            DeviceName = settings.DeviceName,
            Profile = settings.Profile,
            Message = "Starting Omega VPN",
        });

        try
        {
            var startInfo = RuntimeLaunchPlan.Create(settings, paths);
            runtimeProcess = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            runtimeProcess.OutputDataReceived += (_, args) => WriteLog(args.Data);
            runtimeProcess.ErrorDataReceived += (_, args) => WriteLog(args.Data);
            runtimeProcess.Exited += RuntimeProcess_Exited;

            OpenLog();
            if (!runtimeProcess.Start())
            {
                SetStatus(ConnectionDisplayState.Error, "Не удалось запустить клиент", "Process.Start вернул false.");
                return;
            }

            runtimeProcess.BeginOutputReadLine();
            runtimeProcess.BeginErrorReadLine();
            await File.WriteAllTextAsync(paths.PidPath, runtimeProcess.Id.ToString());

            lifecycleStore.Write(new LifecycleSnapshot
            {
                State = "connecting",
                Pid = runtimeProcess.Id,
                ServerEndpoint = settings.ServerEndpoint,
                DeviceName = settings.DeviceName,
                Profile = settings.Profile,
                Message = "Omega VPN is starting",
            });

            SetStatus(ConnectionDisplayState.Connecting, "Подключение", "Omega VPN запускается.");
            ConnectButton.Content = "Отключить";
        }
        catch (Exception ex)
        {
            lifecycleStore.Write(new LifecycleSnapshot
            {
                State = "failed",
                ServerEndpoint = settings.ServerEndpoint,
                DeviceName = settings.DeviceName,
                Profile = settings.Profile,
                Message = "Failed to start Omega VPN",
                LastError = ex.Message,
            });
            SetStatus(ConnectionDisplayState.Error, "Ошибка запуска", ex.Message);
        }
    }

    private async Task DisconnectAsync()
    {
        if (runtimeProcess is not { HasExited: false } process)
        {
            runtimeProcess = null;
            ConnectButton.Content = "Подключить";
            SetStatus(ConnectionDisplayState.Disconnected, "Отключено", "Omega VPN не запущен.");
            return;
        }

        disconnectRequested = true;
        ControlFile.RequestStop(paths.ControlPath);
        lifecycleStore.Write(new LifecycleSnapshot
        {
            State = "stopping",
            Pid = process.Id,
            ServerEndpoint = ServerBox.Text,
            DeviceName = DeviceNameBox.Text,
            Profile = "gaming",
            Message = "Stop requested by GUI",
        });
        SetStatus(ConnectionDisplayState.Stopping, "Отключение", "Останавливаю VPN и очищаю маршруты.");

        var exited = await WaitForExitAsync(process, TimeSpan.FromSeconds(15));
        if (!exited && !process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            SetStatus(ConnectionDisplayState.Error, "Клиент остановлен принудительно", "Cleanup мог не завершиться. Запустите подключение заново, если маршруты требуют восстановления.");
        }
    }

    private async void RuntimeProcess_Exited(object? sender, EventArgs e)
    {
        var exitCode = runtimeProcess?.ExitCode;
        await Dispatcher.InvokeAsync(() =>
        {
            ConnectButton.Content = "Подключить";
            runtimeProcess = null;
            logWriter?.Flush();
            logWriter?.Dispose();
            logWriter = null;

            if (disconnectRequested)
            {
                lifecycleStore.Write(new LifecycleSnapshot
                {
                    State = "disconnected",
                    ServerEndpoint = ServerBox.Text,
                    DeviceName = DeviceNameBox.Text,
                    Profile = "gaming",
                    Message = "Omega VPN stopped",
                });
                SetStatus(ConnectionDisplayState.Disconnected, "Отключено", "VPN остановлен.");
            }
            else
            {
                lifecycleStore.Write(new LifecycleSnapshot
                {
                    State = "failed",
                    ServerEndpoint = ServerBox.Text,
                    DeviceName = DeviceNameBox.Text,
                    Profile = "gaming",
                    Message = "Omega VPN exited",
                    LastError = exitCode.HasValue ? $"Exit code {exitCode.Value}" : null,
                });
                SetStatus(ConnectionDisplayState.Error, "Клиент остановился", exitCode.HasValue ? $"Exit code {exitCode.Value}" : "Процесс завершился.");
            }
        });
    }

    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private void RefreshDiagnostics()
    {
        if (!File.Exists(paths.DiagnosticsPath))
        {
            return;
        }

        try
        {
            var snapshot = ClientDiagnosticsSnapshot.FromJson(File.ReadAllText(paths.DiagnosticsPath));
            var view = DiagnosticsStatusMapper.ToView(snapshot);
            ApplyDiagnosticsView(view);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void ApplyDiagnosticsView(DiagnosticsView view)
    {
        SetStatus(view.State, view.StatusText, view.Message);
        QualityText.Text = view.PathQuality;
        RttText.Text = view.HandshakeRtt;
        MtuText.Text = view.EffectiveMtu;
        TransportText.Text = view.Transport;
        TunnelIpText.Text = view.TunnelIp;
        if (view.State is ConnectionDisplayState.Connected or ConnectionDisplayState.Degraded or ConnectionDisplayState.Connecting)
        {
            ConnectButton.Content = "Отключить";
        }
    }

    private void SetStatus(ConnectionDisplayState state, string title, string message)
    {
        StatusText.Text = title;
        StatusMessage.Text = message;
        ConnectionProgress.Visibility =
            state is ConnectionDisplayState.Connecting or ConnectionDisplayState.Stopping
                ? Visibility.Visible
                : Visibility.Collapsed;
        StatusDot.Background = new SolidColorBrush(state switch
        {
            ConnectionDisplayState.Connected => System.Windows.Media.Color.FromRgb(55, 195, 138),
            ConnectionDisplayState.Degraded => System.Windows.Media.Color.FromRgb(238, 188, 78),
            ConnectionDisplayState.Connecting or ConnectionDisplayState.Stopping => System.Windows.Media.Color.FromRgb(77, 157, 224),
            ConnectionDisplayState.Error => System.Windows.Media.Color.FromRgb(232, 93, 93),
            _ => System.Windows.Media.Color.FromRgb(93, 106, 117),
        });

        if (trayIcon is not null)
        {
            trayIcon.Text = $"Omega VPN - {title}";
        }
    }

    private ConnectionSettings ReadSettings()
    {
        return new ConnectionSettings
        {
            ServerEndpoint = ServerBox.Text,
            DeviceId = DeviceIdBox.Text,
            DeviceToken = DeviceTokenBox.Password,
            DeviceName = string.IsNullOrWhiteSpace(DeviceNameBox.Text) ? Environment.MachineName : DeviceNameBox.Text,
            Transport = SelectedComboText(TransportBox, "auto"),
            KillSwitch = SelectedComboText(KillSwitchBox, "soft"),
            DnsLeakGuard = SelectedComboText(DnsLeakGuardBox, "warn"),
            Autostart = AutostartBox.IsChecked == true,
        };
    }

    private void LoadSettings()
    {
        var settings = configStore.Load();
        ServerBox.Text = settings.ServerEndpoint;
        DeviceIdBox.Text = settings.DeviceId;
        DeviceTokenBox.Password = settings.DeviceToken;
        DeviceNameBox.Text = string.IsNullOrWhiteSpace(settings.DeviceName) ? Environment.MachineName : settings.DeviceName;
        SelectComboText(TransportBox, settings.Transport);
        SelectComboText(KillSwitchBox, settings.KillSwitch);
        SelectComboText(DnsLeakGuardBox, settings.DnsLeakGuard);
        AutostartBox.IsChecked = settings.Autostart;
    }

    private static string SelectedComboText(System.Windows.Controls.ComboBox comboBox, string fallback)
    {
        return comboBox.SelectedItem is System.Windows.Controls.ComboBoxItem item && item.Content is string value
            ? value
            : fallback;
    }

    private static void SelectComboText(System.Windows.Controls.ComboBox comboBox, string value)
    {
        foreach (var item in comboBox.Items.OfType<System.Windows.Controls.ComboBoxItem>())
        {
            if (string.Equals(item.Content?.ToString(), value, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = item;
                return;
            }
        }
    }

    private void ConfigureTray()
    {
        trayIcon = new Forms.NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Text = "Omega VPN",
            Visible = true,
            ContextMenuStrip = new Forms.ContextMenuStrip(),
        };
        trayIcon.DoubleClick += (_, _) => ShowFromTray();
        trayIcon.ContextMenuStrip.Items.Add("Открыть", null, (_, _) => ShowFromTray());
        trayIcon.ContextMenuStrip.Items.Add("Подключить / отключить", null, async (_, _) =>
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                if (runtimeProcess is { HasExited: false })
                {
                    await DisconnectAsync();
                }
                else
                {
                    await ConnectAsync();
                }
            });
        });
        trayIcon.ContextMenuStrip.Items.Add("Выход", null, async (_, _) =>
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                if (runtimeProcess is { HasExited: false })
                {
                    await DisconnectAsync();
                }
                explicitExitRequested = true;
                Close();
            });
        });
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private static Icon LoadTrayIcon()
    {
        var resource = System.Windows.Application.GetResourceStream(
            new Uri("pack://application:,,,/Assets/omega-vpn.ico", UriKind.Absolute));
        if (resource is null)
        {
            return SystemIcons.Shield;
        }

        using var stream = resource.Stream;
        using var icon = new Icon(stream);
        return (Icon)icon.Clone();
    }

    private void OpenLog()
    {
        Directory.CreateDirectory(paths.StateDirectory);
        logWriter?.Dispose();
        logWriter = new StreamWriter(new FileStream(paths.LogPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true,
        };
        WriteLog("");
        WriteLog("=== Omega VPN GUI launch ===");
    }

    private void WriteLog(string? line)
    {
        if (line is null || logWriter is null)
        {
            return;
        }

        lock (logWriter)
        {
            logWriter.WriteLine(line);
        }
    }

    private void RequestRuntimeStopOnExit()
    {
        if (runtimeProcess is not { HasExited: false } process)
        {
            return;
        }

        try
        {
            ControlFile.RequestStop(paths.ControlPath);
            lifecycleStore.Write(new LifecycleSnapshot
            {
                State = "stopping",
                Pid = process.Id,
                ServerEndpoint = ServerBox.Text,
                DeviceName = DeviceNameBox.Text,
                Profile = "gaming",
                Message = "Stop requested because GUI exited",
            });
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to request runtime stop on GUI exit: {ex.Message}");
        }
    }
}
