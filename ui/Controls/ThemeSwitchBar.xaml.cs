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
        Loaded += (_, _) =>
        {
            SyncFromCurrent();
            _ready = true;
        };
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
