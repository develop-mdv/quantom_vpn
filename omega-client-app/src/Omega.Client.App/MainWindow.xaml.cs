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
    private ClientAppConfig appConfig = new();
    private Forms.NotifyIcon? trayIcon;
    private Process? runtimeProcess;
    private ConnectionSettings? activeSettings;
    private StreamWriter? logWriter;
    private bool disconnectRequested;
    private bool explicitExitRequested;
    private bool profileSelectionChanging;

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
        if (!TryReadSettings(out var settings, out var profileName, out var readError))
        {
            SetStatus(ConnectionDisplayState.Error, "Проверьте код", readError);
            return;
        }

        var validation = ConnectionSettingsValidator.Validate(settings);
        if (validation.Count > 0)
        {
            SetStatus(ConnectionDisplayState.Error, "Проверьте данные", validation[0].Message);
            return;
        }

        var savedProfile = appConfig.UpsertProfile(settings, profileName);
        configStore.SaveState(appConfig);
        RefreshProfiles(savedProfile.Id);
        settings = savedProfile.Settings.Clone();
        activeSettings = settings.Clone();

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
        var settings = CurrentLifecycleSettings();
        lifecycleStore.Write(new LifecycleSnapshot
        {
            State = "stopping",
            Pid = process.Id,
            ServerEndpoint = settings.ServerEndpoint,
            DeviceName = settings.DeviceName,
            Profile = settings.Profile,
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
            var settings = CurrentLifecycleSettings();
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
                    ServerEndpoint = settings.ServerEndpoint,
                    DeviceName = settings.DeviceName,
                    Profile = settings.Profile,
                    Message = "Omega VPN stopped",
                });
                SetStatus(ConnectionDisplayState.Disconnected, "Отключено", "VPN остановлен.");
            }
            else
            {
                lifecycleStore.Write(new LifecycleSnapshot
                {
                    State = "failed",
                    ServerEndpoint = settings.ServerEndpoint,
                    DeviceName = settings.DeviceName,
                    Profile = settings.Profile,
                    Message = "Omega VPN exited",
                    LastError = exitCode.HasValue ? $"Exit code {exitCode.Value}" : null,
                });
                SetStatus(ConnectionDisplayState.Error, "Клиент остановился", exitCode.HasValue ? $"Exit code {exitCode.Value}" : "Процесс завершился.");
            }

            activeSettings = null;
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

    private bool TryReadSettings(out ConnectionSettings settings, out string profileName, out string error)
    {
        var code = ConnectionCodeBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(code))
        {
            var parsed = ConnectionCodeParser.Parse(code);
            if (!parsed.Success || parsed.Settings is null)
            {
                settings = new ConnectionSettings();
                profileName = "";
                error = parsed.ErrorMessage ?? "Код подключения не распознан.";
                return false;
            }

            settings = parsed.Settings.Clone();
            ApplyAdvancedSettings(settings, overwriteDeviceName: false);
            profileName = parsed.ProfileName;
            error = "";
            return true;
        }

        if (SelectedProfile() is { } selectedProfile)
        {
            settings = selectedProfile.Settings.Clone();
            ApplyAdvancedSettings(settings, overwriteDeviceName: true);
            profileName = selectedProfile.Name;
            error = "";
            return true;
        }

        settings = new ConnectionSettings();
        profileName = "";
        error = "Вставьте код подключения или выберите сохраненный профиль.";
        return false;
    }

    private void LoadSettings()
    {
        appConfig = configStore.LoadState();
        RefreshProfiles(appConfig.SelectedProfileId);
        ApplySelectedProfileSettings();
    }

    private void RefreshProfiles(string? selectedProfileId = null)
    {
        profileSelectionChanging = true;
        ProfileBox.ItemsSource = null;
        ProfileBox.ItemsSource = appConfig.Profiles;
        ProfileBox.DisplayMemberPath = nameof(SavedConnectionProfile.Name);
        ProfileBox.SelectedValuePath = nameof(SavedConnectionProfile.Id);
        ProfileBox.SelectedValue = string.IsNullOrWhiteSpace(selectedProfileId)
            ? appConfig.SelectedProfileId
            : selectedProfileId;
        if (ProfileBox.SelectedItem is null && appConfig.Profiles.Count > 0)
        {
            ProfileBox.SelectedIndex = 0;
        }

        DeleteProfileButton.IsEnabled = ProfileBox.SelectedItem is not null;
        profileSelectionChanging = false;
    }

    private void ApplySelectedProfileSettings()
    {
        var settings = SelectedProfile()?.Settings ?? new ConnectionSettings();
        DeviceNameBox.Text = string.IsNullOrWhiteSpace(settings.DeviceName) ? Environment.MachineName : settings.DeviceName;
        SelectComboText(TransportBox, settings.Transport);
        SelectComboText(KillSwitchBox, settings.KillSwitch);
        SelectComboText(DnsLeakGuardBox, settings.DnsLeakGuard);
        AutostartBox.IsChecked = settings.Autostart;
        DeleteProfileButton.IsEnabled = SelectedProfile() is not null;
    }

    private void ApplyAdvancedSettings(ConnectionSettings settings, bool overwriteDeviceName)
    {
        if (overwriteDeviceName)
        {
            settings.DeviceName = string.IsNullOrWhiteSpace(DeviceNameBox.Text) ? Environment.MachineName : DeviceNameBox.Text;
        }

        settings.Transport = SelectedComboText(TransportBox, "auto");
        settings.KillSwitch = SelectedComboText(KillSwitchBox, "soft");
        settings.DnsLeakGuard = SelectedComboText(DnsLeakGuardBox, "warn");
        settings.Autostart = AutostartBox.IsChecked == true;
    }

    private SavedConnectionProfile? SelectedProfile()
    {
        return ProfileBox.SelectedItem as SavedConnectionProfile;
    }

    private ConnectionSettings CurrentLifecycleSettings()
    {
        return activeSettings?.Clone()
            ?? SelectedProfile()?.Settings.Clone()
            ?? new ConnectionSettings();
    }

    private static string SelectedComboText(System.Windows.Controls.ComboBox comboBox, string fallback)
    {
        return comboBox.SelectedItem is System.Windows.Controls.ComboBoxItem item && item.Content is string value
            ? value
            : fallback;
    }

    private void ProfileBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (profileSelectionChanging)
        {
            return;
        }

        if (SelectedProfile() is { } selectedProfile)
        {
            appConfig.SelectedProfileId = selectedProfile.Id;
            configStore.SaveState(appConfig);
            ConnectionCodeBox.Clear();
        }

        ApplySelectedProfileSettings();
    }

    private void SaveCodeButton_Click(object sender, RoutedEventArgs e)
    {
        var parsed = ConnectionCodeParser.Parse(ConnectionCodeBox.Text);
        if (!parsed.Success || parsed.Settings is null)
        {
            SetStatus(ConnectionDisplayState.Error, "Проверьте код", parsed.ErrorMessage ?? "Код подключения не распознан.");
            return;
        }

        var settings = parsed.Settings.Clone();
        ApplyAdvancedSettings(settings, overwriteDeviceName: false);
        var savedProfile = appConfig.UpsertProfile(settings, parsed.ProfileName);
        configStore.SaveState(appConfig);
        RefreshProfiles(savedProfile.Id);
        ConnectionCodeBox.Clear();
        ApplySelectedProfileSettings();
        SetStatus(ConnectionDisplayState.Disconnected, "Профиль сохранен", "Теперь это подключение можно выбрать из списка.");
    }

    private void DeleteProfileButton_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedProfile() is not { } selectedProfile)
        {
            return;
        }

        appConfig.Profiles.RemoveAll(profile => string.Equals(profile.Id, selectedProfile.Id, StringComparison.Ordinal));
        appConfig.SelectedProfileId = appConfig.Profiles.FirstOrDefault()?.Id ?? "";
        configStore.SaveState(appConfig);
        RefreshProfiles(appConfig.SelectedProfileId);
        ApplySelectedProfileSettings();
        SetStatus(ConnectionDisplayState.Disconnected, "Профиль удален", "Выберите другой профиль или добавьте новый код подключения.");
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
            var settings = CurrentLifecycleSettings();
            lifecycleStore.Write(new LifecycleSnapshot
            {
                State = "stopping",
                Pid = process.Id,
                ServerEndpoint = settings.ServerEndpoint,
                DeviceName = settings.DeviceName,
                Profile = settings.Profile,
                Message = "Stop requested because GUI exited",
            });
        }
        catch (Exception ex)
        {
            WriteLog($"Failed to request runtime stop on GUI exit: {ex.Message}");
        }
    }
}
