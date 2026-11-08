using System.Diagnostics;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

public sealed partial class SettingsPage : Page
{
    private ClientUpdateInfo? _pendingUpdate;
    private string? _downloadedUpdatePath;

    public SettingsPage()
    {
        InitializeComponent();
        ProductVersionText.Text = $"{ProductInfo.Name} {ProductInfo.Version}";
        DataPathText.Text = $"诊断日志：{ClientDiagnosticLog.LogPath}\n规避设置：{DataFolder()}\\evasion.json";
        Loaded += SettingsPage_Loaded;
    }

    private static string DataFolder() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NovaProtect");

    /// <summary>
    /// Reveal the folder rather than launching a shell command, so a user can see
    /// the files instead of being handed a console window.
    /// </summary>
    private void OpenFolder(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Warning;
            UpdateStatusBar.Message = "无法打开目录： " + path;
            UpdateStatusBar.IsOpen = true;
        }
    }

    private void OpenLogFolder_Click(object sender, RoutedEventArgs e) =>
        OpenFolder(Path.GetDirectoryName(ClientDiagnosticLog.LogPath) ?? DataFolder());

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e) => OpenFolder(DataFolder());

    private async void ResetEvasion_Click(object sender, RoutedEventArgs e)
    {
        var confirmed = await DialogService.ConfirmAsync(XamlRoot, "恢复默认规避设置",
            "对抗与规避的档位、种子、探测强度和环境闸门都会回到默认值。已保存的项目文件不受影响。",
            "恢复默认");
        if (!confirmed) return;

        ProtectionSession.Reset();
        UpdateStatusBar.Severity = InfoBarSeverity.Success;
        UpdateStatusBar.Message = "规避设置已恢复默认。";
        UpdateStatusBar.IsOpen = true;
    }

    private async void SettingsPage_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= SettingsPage_Loaded;
        await CheckUpdateAsync(false);
    }

    private void ThemeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ThemeBox.SelectedItem is not ComboBoxItem { Tag: string tag }) return;
        if (App.MainWindow?.Content is FrameworkElement root)
        {
            root.RequestedTheme = tag switch
            {
                "light" => ElementTheme.Light,
                "dark" => ElementTheme.Dark,
                _ => ElementTheme.Default
            };
        }
    }

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e) => await CheckUpdateAsync(true);

    private async void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate is null) return;
        DownloadUpdateButton.IsEnabled = false;
        OpenUpdateButton.Visibility = Visibility.Collapsed;
        UpdateProgressBar.Visibility = Visibility.Visible;
        UpdateProgressBar.Minimum = 0;
        UpdateProgressBar.Maximum = _pendingUpdate.Size;
        UpdateProgressBar.Value = 0;
        UpdateStatusBar.Severity = InfoBarSeverity.Informational;
        UpdateStatusBar.Message = "正在下载并校验更新…";
        try
        {
            var update = _pendingUpdate;
            var progress = new Progress<long>(value => UpdateProgressBar.Value = value);
            var result = await UpdateClient.Shared.DownloadUpdateAsync(update, progress);
            if (result.Download is null)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Error;
                UpdateStatusBar.Message = result.Error ?? "更新下载失败。";
                return;
            }

            _downloadedUpdatePath = result.Download.FilePath;
            UpdateStatusBar.Severity = InfoBarSeverity.Success;
            UpdateStatusBar.Message = $"已完成 {result.Download.Update.FileName} 的大小和 SHA-256 校验。";
            OpenUpdateButton.Visibility = Visibility.Visible;
        }
        finally
        {
            UpdateProgressBar.Visibility = Visibility.Collapsed;
            DownloadUpdateButton.IsEnabled = _pendingUpdate?.IsNewer == true;
        }
    }

    private void OpenUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_downloadedUpdatePath) || !File.Exists(_downloadedUpdatePath))
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Warning;
            UpdateStatusBar.Message = "已校验的安装包不存在，请重新下载。";
            OpenUpdateButton.Visibility = Visibility.Collapsed;
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(_downloadedUpdatePath) { UseShellExecute = true });
            UpdateStatusBar.Severity = InfoBarSeverity.Success;
            UpdateStatusBar.Message = "安装程序已启动，请按向导完成升级。";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Error;
            UpdateStatusBar.Message = "无法启动已校验的安装程序。";
        }
    }

    private async Task CheckUpdateAsync(bool interactive)
    {
        CheckUpdateButton.IsEnabled = false;
        DownloadUpdateButton.Visibility = Visibility.Collapsed;
        OpenUpdateButton.Visibility = Visibility.Collapsed;
        _pendingUpdate = null;
        _downloadedUpdatePath = null;
        UpdateStatusBar.Severity = InfoBarSeverity.Informational;
        UpdateStatusBar.Message = interactive ? "正在检查更新…" : "正在读取更新信息…";
        try
        {
            var result = await UpdateClient.Shared.CheckForUpdateAsync();
            if (result.Update is null)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Warning;
                UpdateStatusBar.Message = result.Error ?? "更新信息暂时不可用。";
                return;
            }

            _pendingUpdate = result.Update;
            if (!result.Update.IsNewer)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Success;
                UpdateStatusBar.Message = $"当前版本 {ProductInfo.Version} 已是最新版本。";
                return;
            }

            UpdateStatusBar.Severity = InfoBarSeverity.Warning;
            UpdateStatusBar.Message = $"发现客户端 {result.Update.ClientVersion}，大小 {FormatSize(result.Update.Size)}。下载后会再次校验 SHA-256。";
            DownloadUpdateButton.Visibility = Visibility.Visible;
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }
}
