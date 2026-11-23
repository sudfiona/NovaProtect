using System.Diagnostics;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

public sealed partial class SettingsPage : Page
{
    private ClientUpdateInfo? _pendingUpdate;
    private string? _downloadedUpdatePath;
    private bool _syncingTheme;
    private bool _syncingLanguage;

    public SettingsPage()
    {
        InitializeComponent();
        // A downloaded update and the pending-update banner live in fields; the
        // cache keeps them reachable after the user looks at another page.
        NavigationCacheMode = NavigationCacheMode.Required;

        try
        {
            ProductVersionText.Text = $"{ProductInfo.Name} {ProductInfo.Version}";
        }
        catch
        {
            ProductVersionText.Text = "NovaProtect";
        }


        // Sync the picker to the live theme WITHOUT applying. XAML must not set
        // SelectedIndex — that fires SelectionChanged during InitializeComponent
        // and would force the theme back to glass.
        try
        {
            _syncingTheme = true;
            ThemeBox.SelectionChanged -= ThemeBox_SelectionChanged;
            ThemeBox.SelectedIndex = NovaTheme.Current switch
            {
                NovaTheme.Pop => 1,
                NovaTheme.Lab => 2,
                _ => 0,
            };
        }
        catch
        {
            // picker is cosmetic; page still works
        }
        finally
        {
            ThemeBox.SelectionChanged += ThemeBox_SelectionChanged;
            _syncingTheme = false;
        }

        // Language picker follows the same rule as the theme picker: sync to the
        // live value without firing the handler.
        try
        {
            _syncingLanguage = true;
            LanguageBox.SelectionChanged -= LanguageBox_SelectionChanged;
            LanguageBox.SelectedIndex = Localizer.Language == UiLanguage.English ? 1 : 0;
        }
        catch
        {
            // picker is cosmetic; page still works
        }
        finally
        {
            LanguageBox.SelectionChanged += LanguageBox_SelectionChanged;
            _syncingLanguage = false;
        }

        // Re-apply on every load and on every language change. Attach pairs the
        // subscription with Unloaded, so this cached page does not stay on the
        // static event after its instance is dropped.
        Localizer.Attach(this, ApplyLanguageToPage);

        Loaded += SettingsPage_Loaded;
    }

    /// <summary>
    /// Resolve a status message on the way in. These are assigned long after the
    /// page loaded, which is exactly when the visual-tree walker has stopped
    /// looking, so the wording has to be settled here. Text that is already
    /// English — an error the update service returned, an exception message —
    /// passes through unchanged.
    /// </summary>
    private Func<string>? _renderStatus;

    private string Tr(string source, string suffix = "")
    {
        _renderStatus = () => Localizer.T(source) + suffix;
        return _renderStatus();
    }

    private string FormatStatus(string template, params object?[] args)
    {
        _renderStatus = () => Localizer.F(template, args);
        return _renderStatus();
    }

    private static string DataFolder()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NovaProtect");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private void OpenFolder(string path)
    {
        try
        {
            // Reject paths that would break the quoted argument or smuggle extra args.
            if (string.IsNullOrWhiteSpace(path) ||
                path.IndexOfAny(new[] { '"', '\n', '\r', '\0' }) >= 0)
            {
                throw new ArgumentException("invalid path");
            }

            var full = Path.GetFullPath(path);
            Directory.CreateDirectory(full);

            var psi = new ProcessStartInfo("explorer.exe")
            {
                UseShellExecute = true,
            };
            psi.ArgumentList.Add(full);
            Process.Start(psi);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidOperationException
            or ArgumentException
            or NotSupportedException)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Warning;
            UpdateStatusBar.Message = Tr("无法打开目录：", path);
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
        UpdateStatusBar.Message = Tr("规避设置已恢复默认。");
        UpdateStatusBar.IsOpen = true;
    }

    private async void SettingsPage_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= SettingsPage_Loaded;
        // The visual tree does not exist in the constructor, so the first
        // translation pass comes from Localizer.Attach's own Loaded handler.
        await CheckUpdateAsync(false);
    }

    private void LanguageBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncingLanguage) return;
        if (LanguageBox.SelectedItem is not ComboBoxItem item || item.Tag is not string tag) return;
        var language = string.Equals(tag, "en", StringComparison.OrdinalIgnoreCase)
            ? UiLanguage.English
            : UiLanguage.ChineseSimplified;
        if (Localizer.Language == language) return;
        // Raises Changed, which re-applies the page and the window shell.
        Localizer.SetLanguage(language);
    }

    /// <summary>
    /// Rewrite every localized element on this page. The ComboBox items are set
    /// explicitly: their visuals only exist while the popup is open, so the
    /// recursive Tag walker would never reach them.
    /// </summary>
    private void ApplyLanguageToPage()
    {
        try
        {
            DataPathText.Text = Localizer.F("诊断日志：{0}\n规避设置：{1}\\evasion.json", ClientDiagnosticLog.LogPath, DataFolder());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            DataPathText.Text = Localizer.T("诊断日志：（初始化失败）");
        }
        if (_renderStatus is not null) UpdateStatusBar.Message = _renderStatus();

        for (var i = 0; i < ThemeBox.Items.Count; i++)
        {
            if (ThemeBox.Items[i] is not ComboBoxItem item || item.Tag is not string themeTag) continue;
            item.Content = themeTag switch
            {
                "glass" => Localizer.Get("settings.theme.glass"),
                "pop" => Localizer.Get("settings.theme.pop"),
                "lab" => Localizer.Get("settings.theme.lab"),
                _ => item.Content,
            };
        }

        for (var i = 0; i < LanguageBox.Items.Count; i++)
        {
            if (LanguageBox.Items[i] is not ComboBoxItem item || item.Tag is not string langTag) continue;
            item.Content = Localizer.Get(
                string.Equals(langTag, "en", StringComparison.OrdinalIgnoreCase) ? "lang.en" : "lang.zh");
        }
    }

    private void ThemeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncingTheme) return;
        if (ThemeBox.SelectedItem is not ComboBoxItem { Tag: string tag }) return;
        // No-op when the picker already matches the live theme.
        if (string.Equals(tag, NovaTheme.Current, StringComparison.OrdinalIgnoreCase)) return;
        if (App.MainWindow?.Content is FrameworkElement root)
        {
            NovaTheme.Apply(root, tag);
            try
            {
                File.WriteAllText(Path.Combine(DataFolder(), "ui-theme.txt"), NovaTheme.Current);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // best-effort
            }
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
        UpdateStatusBar.Message = Tr("正在下载并校验更新…");
        try
        {
            var update = _pendingUpdate;
            var progress = new Progress<long>(value => UpdateProgressBar.Value = value);
            var result = await UpdateClient.Shared.DownloadUpdateAsync(update, progress);
            if (result.Download is null)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Error;
                UpdateStatusBar.Message = result.Error is null ? Tr("更新下载失败。") : Tr(result.Error);
                return;
            }

            _downloadedUpdatePath = result.Download.FilePath;
            UpdateStatusBar.Severity = InfoBarSeverity.Success;
            UpdateStatusBar.Message = FormatStatus("已完成 {0} 的大小和 SHA-256 校验。", result.Download.Update.FileName);
            OpenUpdateButton.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Error;
            UpdateStatusBar.Message = Tr("更新失败：", ex.Message);
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
            UpdateStatusBar.Message = Tr("已校验的安装包不存在，请重新下载。");
            OpenUpdateButton.Visibility = Visibility.Collapsed;
            return;
        }

        try
        {
            // Only launch installers we wrote under our private temp tree.
            var updatesRoot = Path.Combine(Path.GetTempPath(), "NovaProtect", "updates");
            var full = Path.GetFullPath(_downloadedUpdatePath);
            if (!full.StartsWith(Path.GetFullPath(updatesRoot), StringComparison.OrdinalIgnoreCase)
                || !full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Error;
                UpdateStatusBar.Message = Tr("安装包路径异常，已拒绝启动。");
                return;
            }
            Process.Start(new ProcessStartInfo(full) { UseShellExecute = true });
            UpdateStatusBar.Severity = InfoBarSeverity.Success;
            UpdateStatusBar.Message = Tr("安装程序已启动，请按向导完成升级。");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Error;
            UpdateStatusBar.Message = Tr("无法启动已校验的安装程序。");
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
        UpdateStatusBar.Message = Tr(interactive ? "正在检查更新…" : "正在读取更新信息…");
        try
        {
            var result = await UpdateClient.Shared.CheckForUpdateAsync();
            if (result.Update is null)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Warning;
                UpdateStatusBar.Message = result.Error is null ? Tr("更新信息暂时不可用。") : Tr(result.Error);
                return;
            }

            _pendingUpdate = result.Update;
            if (!result.Update.IsNewer)
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Success;
                UpdateStatusBar.Message = FormatStatus("当前版本 {0} 已是最新版本。", ProductInfo.Version);
                return;
            }

            UpdateStatusBar.Severity = InfoBarSeverity.Warning;
            UpdateStatusBar.Message = FormatStatus("发现客户端 {0}，大小 {1}。下载后会再次校验 SHA-256。",
                result.Update.ClientVersion, FormatSize(result.Update.Size));
            DownloadUpdateButton.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            UpdateStatusBar.Severity = InfoBarSeverity.Error;
            UpdateStatusBar.Message = Tr("检查更新失败：", ex.Message);
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
