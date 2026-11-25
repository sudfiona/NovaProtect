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
    private readonly Windows.UI.ViewManagement.UISettings _visualSettings = new();
    private readonly System.Diagnostics.Stopwatch _motionClock = new();
    private readonly Microsoft.UI.Dispatching.DispatcherQueueTimer _motionTimer;
    private bool _motionViewLoaded;
    private bool _wideDock;

    public nint WindowHandle { get; }

    public MainWindow()
    {
        InitializeComponent();
        // Ambient artwork is opted in by default even when Windows disables UI transitions.
        _motionTimer = RootGrid.DispatcherQueue.CreateTimer();
        _motionTimer.Interval = TimeSpan.FromMilliseconds(1000d / 30);
        _motionTimer.Tick += (_, _) => RenderThemeMotion();
        Title = ProductInfo.Name;
        VersionText.Text = $"v{ProductInfo.DisplayVersion}";
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

        NovaTheme.Restore(RootGrid);
        NovaTheme.Changed += OnThemeChanged;
        WorkspaceGrid.SizeChanged += (_, args) =>
        {
            bool wideDock = args.NewSize.Width >= 1040;
            if (wideDock == _wideDock) return;
            _wideDock = wideDock;
            ApplyThemeLayout();
        };
        RootGrid.Loaded += (_, _) => SetMotionViewLoaded(true);
        RootGrid.Unloaded += (_, _) => SetMotionViewLoaded(false);
        appWindow.Changed += (_, _) => UpdateBackdropMotion();
        Closed += (_, _) =>
        {
            NovaTheme.Changed -= OnThemeChanged;
            SetMotionViewLoaded(false);
        };
        ApplyThemeLayout();
        NavigateTo("protect");

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

    private void OnThemeChanged(object? sender, EventArgs args) => ApplyThemeLayout();

    private void ApplyThemeLayout()
    {
        var theme = NovaTheme.Current;
        bool glass = theme == NovaTheme.Glass;
        bool lab = theme == NovaTheme.Lab;
        bool pop = theme == NovaTheme.Pop;
        bool blackHole = theme == NovaTheme.BlackHole;
        bool sideRail = glass || lab;

        LeftRailColumn.Width = new GridLength(glass ? 202 : 0);
        RightRailColumn.Width = new GridLength(lab ? 190 : 0);
        Grid.SetRow(NavigationCard, sideRail ? 1 : pop ? 0 : 3);
        Grid.SetRowSpan(NavigationCard, sideRail ? 2 : 1);
        Grid.SetColumn(NavigationCard, glass ? 0 : lab ? 2 : 1);
        NavigationCard.Margin = glass ? new Thickness(0, 0, 12, 0)
            : lab ? new Thickness(12, 0, 0, 0)
            : pop ? new Thickness(0, 4, 0, 6) : new Thickness(0, 8, 0, 0);
        NavigationCard.Padding = sideRail ? new Thickness(8, 12, 8, 10) : new Thickness(6, 2, 6, 2);
        WorkspaceLabel.Visibility = sideRail ? Visibility.Visible : Visibility.Collapsed;

        RadioButton[] items = [NavProtect, NavEvasion, NavInspect, NavActivity, NavChangelog, NavSettingsBtn];
        int columns = sideRail ? 1 : _wideDock ? 6 : 3;
        NavigationItems.RowDefinitions.Clear();
        NavigationItems.ColumnDefinitions.Clear();
        for (int i = 0; i < columns; i++)
            NavigationItems.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (int i = 0; i < items.Length / columns; i++)
            NavigationItems.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        NavigationItems.ColumnSpacing = sideRail ? 0 : 4;
        for (int i = 0; i < items.Length; i++)
        {
            Grid.SetRow(items[i], i / columns);
            Grid.SetColumn(items[i], i % columns);
            items[i].HorizontalAlignment = HorizontalAlignment.Stretch;
            items[i].Padding = sideRail ? new Thickness(9, 7, 6, 7) : new Thickness(5, 2, 3, 2);
            items[i].MinHeight = sideRail ? 46 : 38;
        }

        WorkspaceGrid.Padding = glass ? new Thickness(18, 6, 18, 16)
            : lab ? new Thickness(8, 4, 8, 8) : new Thickness(12, 0, 12, 12);
        StatusStrip.MinHeight = pop ? 54 : 46;
        StatusStrip.Padding = blackHole ? new Thickness(18, 0, 18, 0) : new Thickness(12, 5, 12, 5);
        PageTitleText.FontSize = blackHole ? 32 : pop ? 23 : lab ? 15 : 19;
        Singularity.Width = _wideDock ? 300 : 232;
        Singularity.Height = _wideDock ? 150 : 116;
        Singularity.Visibility = blackHole ? Visibility.Visible : Visibility.Collapsed;
        ThemeOrnament.SetTheme(theme);
        RenderThemeMotion();
    }

    private void SetMotionViewLoaded(bool loaded)
    {
        _motionViewLoaded = loaded;
        UpdateBackdropMotion();
    }

    private void UpdateBackdropMotion()
    {
        bool shouldPlay = _motionViewLoaded && AppWindow.IsVisible &&
            AppWindow.Presenter is not OverlappedPresenter { State: OverlappedPresenterState.Minimized } &&
            PauseThemeMotion.IsChecked != true;
        if (shouldPlay == _motionTimer.IsRunning) return;
        if (shouldPlay)
        {
            _motionClock.Start();
            _motionTimer.Start();
        }
        else
        {
            _motionTimer.Stop();
            _motionClock.Stop();
        }
    }

    private void OnThemeMotionClick(object sender, RoutedEventArgs e)
    {
        UpdateMotionLabel();
        UpdateBackdropMotion();
    }

    private void UpdateMotionLabel()
    {
        bool paused = PauseThemeMotion.IsChecked == true;
        bool chinese = Services.Localizer.Language == Services.UiLanguage.ChineseSimplified;
        string label = paused ? (chinese ? "播放主题动效" : "Play theme animation")
                              : (chinese ? "暂停主题动效" : "Pause theme animation");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(PauseThemeMotion, label);
        ToolTipService.SetToolTip(PauseThemeMotion, label);
        if (PauseThemeMotion.Content is FontIcon icon)
            icon.Glyph = paused ? "\uE768" : "\uE769";
    }

    private void RenderThemeMotion()
    {
        double seconds = _motionClock.Elapsed.TotalSeconds;
        if (NovaTheme.Current == NovaTheme.BlackHole)
            Singularity.RenderFrame(seconds);
        else
            ThemeOrnament.RenderFrame(seconds);
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
        if (PageHost is null || !_visualSettings.AnimationsEnabled) return;
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

    /// <summary>Re-label every piece of shell chrome. The nav buttons carry the
    /// glyph in <c>Tag</c>, so their text cannot use the <c>loc:</c> convention
    /// and has to be assigned here.</summary>
    private void ApplyLanguage()
    {
        UpdateMotionLabel();
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
