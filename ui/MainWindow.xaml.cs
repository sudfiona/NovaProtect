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
    /// <summary>Route → status-strip copy. Keys, not text: the strip has to
    /// follow the UI language, and the language can change while a page is up.</summary>
    private static readonly (string Tag, string TitleKey, string HintKey)[] PageMeta =
    {
        ("protect", "nav.protect", "hint.protect"),
        ("evasion", "nav.evasion", "hint.evasion"),
        ("inspect", "nav.inspect", "hint.inspect"),
        ("activity", "nav.activity", "hint.activity"),
        ("changelog", "nav.changelog", "hint.changelog"),
        ("settings", "nav.settings", "hint.settings"),
    };

    private string _currentRoute = "protect";

    public nint WindowHandle { get; }

    public MainWindow()
    {
        InitializeComponent();
        Title = ProductInfo.Name;
        VersionText.Text = $"v{ProductInfo.Version}";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        ApplyLanguage();
        Services.Localizer.Changed += (_, _) => ApplyLanguage();

        WindowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(WindowHandle);
        var appWindow = AppWindow.GetFromWindowId(windowId);
        // An unpackaged WinUI window does not inherit its exe icon for the
        // taskbar and Alt-Tab entry; without this call they fall back to the
        // generic blank icon while the custom title bar shows the logo.
        ApplyWindowIcon(appWindow);
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

    private static void ApplyWindowIcon(AppWindow appWindow)
    {
        try
        {
            var icon = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "NovaProtect.ico");
            if (System.IO.File.Exists(icon))
            {
                appWindow.SetIcon(icon);
                return;
            }
            // Some packaging layouts drop the .ico but keep the PNG the title bar
            // uses; SetIcon accepts either, so fall back instead of showing the
            // generic taskbar icon.
            var png = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "NovaProtect.png");
            if (System.IO.File.Exists(png)) appWindow.SetIcon(png);
        }
        catch (Exception ex)
        {
            Services.ClientDiagnosticLog.Error("设置窗口图标失败", ex);
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

    /// <summary>Re-label every piece of shell chrome. The nav buttons carry the
    /// glyph in <c>Tag</c>, so their text cannot use the <c>loc:</c> convention
    /// and has to be assigned here.</summary>
    private void ApplyLanguage()
    {
        if (WorkspaceLabel is not null)
            WorkspaceLabel.Text = Services.Localizer.Get("nav.workspace");

        ApplyNavLabel(NavProtect, "nav.protect");
        ApplyNavLabel(NavEvasion, "nav.evasion");
        ApplyNavLabel(NavInspect, "nav.inspect");
        ApplyNavLabel(NavActivity, "nav.activity");
        ApplyNavLabel(NavChangelog, "nav.changelog");
        ApplyNavLabel(NavSettingsBtn, "nav.settings");

        UpdatePageChrome(_currentRoute);
    }

    private static void ApplyNavLabel(RadioButton? button, string key)
    {
        if (button is null) return;
        button.Content = Services.Localizer.Get(key);
    }

    private void UpdatePageChrome(string tag)
    {
        foreach (var (t, titleKey, hintKey) in PageMeta)
        {
            if (!string.Equals(t, tag, StringComparison.Ordinal)) continue;
            if (PageTitleText is not null) PageTitleText.Text = Services.Localizer.Get(titleKey);
            if (PageHintText is not null) PageHintText.Text = Services.Localizer.Get(hintKey);
            if (StatusChip is not null) StatusChip.Text = Services.Localizer.Get("status.ready");
            return;
        }
        if (PageTitleText is not null) PageTitleText.Text = "NovaProtect";
        if (PageHintText is not null) PageHintText.Text = Services.Localizer.Get("app.tagline");
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
        _currentRoute = tag;
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
            if (StatusChip is not null) StatusChip.Text = Services.Localizer.Get("status.loadfailed");
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
