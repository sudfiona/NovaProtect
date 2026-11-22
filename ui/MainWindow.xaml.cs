using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using NovaProtect.UI.Models;
using NovaProtect.UI.Pages;
using Windows.Graphics;
using WinRT.Interop;
using Color = Windows.UI.Color;

namespace NovaProtect.UI;

public sealed partial class MainWindow : Window
{
    private static readonly (string Tag, string Title, string Hint)[] PageMeta =
    {
        ("protect", "保护项目", "选择目标、调整策略、构建受保护版本"),
        ("evasion", "对抗与规避", "静态清洗 · 动态探测 · 内核探针 · 环境闸门"),
        ("inspect", "检查工具", "只读查看 PE、水印、虚拟文件与本机 ID"),
        ("activity", "运行记录", "本机保存的历次保护结果"),
        ("changelog", "更新日志", "与 GitHub Releases 同步的版本说明"),
        ("settings", "设置", "主题 · 数据目录 · 在线更新"),
    };

    public nint WindowHandle { get; }

    public MainWindow()
    {
        InitializeComponent();
        Title = ProductInfo.Name;
        VersionText.Text = $"v{ProductInfo.Version}";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        WindowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(WindowHandle);
        var appWindow = AppWindow.GetFromWindowId(windowId);
        appWindow.Resize(new SizeInt32(1280, 860));

        const int minWidth = 1024;
        const int minHeight = 680;
        appWindow.Changed += (_, args) =>
        {
            if (!args.DidSizeChange) return;
            var size = appWindow.Size;
            if (size.Width >= minWidth && size.Height >= minHeight) return;
            appWindow.Resize(new SizeInt32(
                Math.Max(size.Width, minWidth),
                Math.Max(size.Height, minHeight)));
        };

        // Open on protect
        NavigateTo("protect");

        RootGrid.Loaded += (_, _) =>
        {
            if (RootGrid.Resources["AuroraPulse"] is Storyboard pulse) pulse.Begin();
            PlayBootSequence();
        };

        // Restore visual theme (glass | pop | lab)
        try
        {
            var themeFile = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NovaProtect", "ui-theme.txt");
            if (System.IO.File.Exists(themeFile) && Content is FrameworkElement root)
            {
                var saved = System.IO.File.ReadAllText(themeFile).Trim();
                NovaTheme.Apply(root, saved);
                Services.ClientDiagnosticLog.Info($"UI theme restored: {NovaTheme.Current}");
            }
        }
        catch (Exception ex)
        {
            Services.ClientDiagnosticLog.Error("theme restore failed", ex);
        }

        if (Content is FrameworkElement fe)
        {
            fe.ActualThemeChanged += (_, _) =>
            {
                ApplyTitleBarTheme(fe.ActualTheme);
                fe.DispatcherQueue.TryEnqueue(() => ApplyTitleBarTheme(fe.ActualTheme));
            };
            ApplyTitleBarTheme(fe.ActualTheme);
        }
    }

    private void ApplyTitleBarTheme(ElementTheme theme)
    {
        try
        {
            var dark = theme == ElementTheme.Dark;
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(WindowHandle);
            var appWindow = AppWindow.GetFromWindowId(windowId);
            if (appWindow.TitleBar is null) return;

            appWindow.TitleBar.ForegroundColor = dark ? Colors.White : Colors.Black;
            appWindow.TitleBar.BackgroundColor = Colors.Transparent;
            appWindow.TitleBar.ButtonBackgroundColor = Colors.Transparent;
            appWindow.TitleBar.ButtonHoverBackgroundColor = dark
                ? Color.FromArgb(40, 255, 255, 255)
                : Color.FromArgb(30, 0, 0, 0);
            appWindow.TitleBar.ButtonPressedBackgroundColor = dark
                ? Color.FromArgb(70, 255, 255, 255)
                : Color.FromArgb(45, 0, 0, 0);
            appWindow.TitleBar.InactiveForegroundColor = dark
                ? Color.FromArgb(140, 255, 255, 255)
                : Color.FromArgb(140, 0, 0, 0);
        }
        catch
        {
            // cosmetic
        }
    }

    private void PlayPageEnter()
    {
        if (PageHost is null) return;
        var t = new DoubleAnimation
        {
            From = 0,
            To = 1,
            Duration = new Duration(TimeSpan.FromMilliseconds(280)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(t, PageHost);
        Storyboard.SetTargetProperty(t, "Opacity");
        var s = new DoubleAnimation
        {
            From = 0.985,
            To = 1,
            Duration = new Duration(TimeSpan.FromMilliseconds(320)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(s, PageHost);
        Storyboard.SetTargetProperty(s, "(UIElement.RenderTransform).(CompositeTransform.ScaleX)");
        var s2 = new DoubleAnimation
        {
            From = 0.985,
            To = 1,
            Duration = new Duration(TimeSpan.FromMilliseconds(320)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(s2, PageHost);
        Storyboard.SetTargetProperty(s2, "(UIElement.RenderTransform).(CompositeTransform.ScaleY)");
        if (PageHost.RenderTransform is not CompositeTransform)
            PageHost.RenderTransform = new CompositeTransform();
        var sb = new Storyboard();
        sb.Children.Add(t);
        sb.Children.Add(s);
        sb.Children.Add(s2);
        sb.Begin();
    }

    private void PlayBootSequence()
    {
        if (BootVeil is null) return;
        BootVeil.Fill = new SolidColorBrush(Color.FromArgb(255, 248, 250, 255));
        var fade = new DoubleAnimation
        {
            From = 1,
            To = 0,
            Duration = new Duration(TimeSpan.FromMilliseconds(420)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(fade, BootVeil);
        Storyboard.SetTargetProperty(fade, "Opacity");
        var sb = new Storyboard();
        sb.Children.Add(fade);
        sb.Begin();
    }

    private void UpdatePageChrome(string tag)
    {
        foreach (var (t, title, hint) in PageMeta)
        {
            if (!string.Equals(t, tag, StringComparison.Ordinal)) continue;
            if (PageTitleText is not null) PageTitleText.Text = title;
            if (PageHintText is not null) PageHintText.Text = hint;
            if (StatusChip is not null) StatusChip.Text = "就绪";
            return;
        }
        if (PageTitleText is not null) PageTitleText.Text = "NovaProtect";
        if (PageHintText is not null) PageHintText.Text = "代码保护工作台";
    }

    private string? RouteOf(RadioButton? btn) =>
        btn switch
        {
            null => null,
            _ when ReferenceEquals(btn, NavProtect) => "protect",
            _ when ReferenceEquals(btn, NavEvasion) => "evasion",
            _ when ReferenceEquals(btn, NavInspect) => "inspect",
            _ when ReferenceEquals(btn, NavActivity) => "activity",
            _ when ReferenceEquals(btn, NavChangelog) => "changelog",
            _ when ReferenceEquals(btn, NavSettingsBtn) => "settings",
            _ => null,
        };

    private void SelectNav(string tag)
    {
        var map = new (string Route, RadioButton? Btn)[]
        {
            ("protect", NavProtect),
            ("evasion", NavEvasion),
            ("inspect", NavInspect),
            ("activity", NavActivity),
            ("changelog", NavChangelog),
            ("settings", NavSettingsBtn),
        };
        foreach (var (route, btn) in map)
        {
            if (btn is null) continue;
            btn.Checked -= Nav_Checked;
            btn.IsChecked = string.Equals(route, tag, StringComparison.Ordinal);
            btn.Checked += Nav_Checked;
        }
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        var route = RouteOf(sender as RadioButton);
        if (route is null) return;
        NavigateTo(route);
    }

    private void Navigate(Type page, string tag)
    {
        UpdatePageChrome(tag);
        try
        {
            if (PageHost is null) return;
            if (PageHost.CurrentSourcePageType == page) return;
            PageHost.Navigate(page);
            PlayPageEnter();
        }
        catch (Exception ex)
        {
            if (StatusChip is not null) StatusChip.Text = "页面加载失败";
            if (PageHintText is not null) PageHintText.Text = ex.Message;
            Services.ClientDiagnosticLog.Error($"Navigate {page.Name} failed", ex);
        }
    }

    /// <summary>Public entry used by pages.</summary>
    public void NavigateTo(string tag)
    {
        SelectNav(tag);
        Navigate(tag switch
        {
            "protect" => typeof(ProtectPage),
            "evasion" => typeof(EvasionPage),
            "inspect" => typeof(InspectPage),
            "activity" => typeof(ActivityPage),
            "changelog" => typeof(ChangelogPage),
            "settings" => typeof(SettingsPage),
            _ => typeof(ProtectPage),
        }, tag);
    }
}
