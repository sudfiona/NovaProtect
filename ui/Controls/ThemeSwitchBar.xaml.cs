using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NovaProtect.UI.Controls;

/// <summary>Theme chips for the main window.</summary>
public sealed partial class ThemeSwitchBar : UserControl
{
    public ThemeSwitchBar()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            NovaTheme.Changed += OnThemeChanged;
            Services.Localizer.Changed += OnLanguageChanged;
            ApplyLanguage();
            SyncFromCurrent();
        };
        Unloaded += (_, _) =>
        {
            NovaTheme.Changed -= OnThemeChanged;
            Services.Localizer.Changed -= OnLanguageChanged;
        };
    }

    private void OnThemeChanged(object? sender, EventArgs e) => SyncFromCurrent();
    private void OnLanguageChanged(object? sender, EventArgs e) => ApplyLanguage();

    /// <summary>Chip text only. <c>Tag</c> carries the theme id, so these cannot
    /// go through the <c>loc:</c> Tag convention.</summary>
    private void ApplyLanguage()
    {
        BlackHoleBtn.Content = Services.Localizer.Get("theme.blackhole");
        GlassBtn.Content = Services.Localizer.Get("theme.glass");
        PopBtn.Content = Services.Localizer.Get("theme.pop");
        LabBtn.Content = Services.Localizer.Get("theme.lab");
    }

    private void SyncFromCurrent()
    {
        BlackHoleBtn.IsChecked = NovaTheme.Current == NovaTheme.BlackHole;
        GlassBtn.IsChecked = NovaTheme.Current == NovaTheme.Glass;
        PopBtn.IsChecked = NovaTheme.Current == NovaTheme.Pop;
        LabBtn.IsChecked = NovaTheme.Current == NovaTheme.Lab;
    }

    private void OnThemeClick(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string theme } &&
            App.MainWindow?.Content is FrameworkElement root)
            NovaTheme.Select(root, theme);
    }
}
