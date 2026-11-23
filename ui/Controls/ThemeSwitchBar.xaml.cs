using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NovaProtect.UI.Controls;

/// <summary>Theme chips: glass / pop / lab.</summary>
public sealed partial class ThemeSwitchBar : UserControl
{
    private bool _ready;

    public ThemeSwitchBar()
    {
        InitializeComponent();
        // The bar lives in the main window for the whole session, so a
        // constructor-time subscription needs no teardown.
        Services.Localizer.Changed += (_, _) => ApplyLanguage();
        Loaded += (_, _) =>
        {
            ApplyLanguage();
            SyncFromCurrent();
            _ready = true;
        };
    }

    /// <summary>Chip text only. <c>Tag</c> carries the theme id, so these cannot
    /// go through the <c>loc:</c> Tag convention.</summary>
    private void ApplyLanguage()
    {
        if (GlassBtn is null || PopBtn is null || LabBtn is null) return;
        GlassBtn.Content = Services.Localizer.Get("theme.glass");
        PopBtn.Content = Services.Localizer.Get("theme.pop");
        LabBtn.Content = Services.Localizer.Get("theme.lab");
    }

    private void SyncFromCurrent()
    {
        if (GlassBtn is null || PopBtn is null || LabBtn is null) return;
        GlassBtn.IsChecked = NovaTheme.Current == NovaTheme.Glass;
        PopBtn.IsChecked = NovaTheme.Current == NovaTheme.Pop;
        LabBtn.IsChecked = NovaTheme.Current == NovaTheme.Lab;
    }

    private void OnThemeClick(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        if (App.MainWindow?.Content is not FrameworkElement root) return;
        var tag = (sender as RadioButton)?.Tag as string ?? NovaTheme.Glass;
        NovaTheme.Apply(root, tag);
        try
        {
            var dir = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "NovaProtect");
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(System.IO.Path.Combine(dir, "ui-theme.txt"), NovaTheme.Current);
        }
        catch (System.Exception)
        {
            // persistence is best-effort
        }
    }
}
