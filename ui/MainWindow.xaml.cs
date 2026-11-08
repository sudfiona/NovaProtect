using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Models;
using NovaProtect.UI.Pages;
using WinRT.Interop;

namespace NovaProtect.UI;

public sealed partial class MainWindow : Window
{
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
        AppWindow.GetFromWindowId(windowId).Resize(new Windows.Graphics.SizeInt32(1180, 800));

        // Open on the protect page: that is the page with work to do. Selecting by
        // tag rather than by index keeps this correct if the menu order changes.
        var firstMenu = NavView.MenuItems.OfType<NavigationViewItem>()
            .FirstOrDefault(item => string.Equals(item.Tag as string, "protect", StringComparison.Ordinal));
        NavView.SelectedItem = firstMenu ?? NavView.MenuItems.OfType<NavigationViewItem>().FirstOrDefault();
        ContentFrame.Navigate(typeof(ProtectPage));
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            Navigate(typeof(SettingsPage));
            return;
        }

        if (args.SelectedItemContainer?.Tag is not string tag) return;
        Navigate(tag switch
        {
            "protect" => typeof(ProtectPage),
            "evasion" => typeof(EvasionPage),
            "inspect" => typeof(InspectPage),
            "activity" => typeof(ActivityPage),
            "changelog" => typeof(ChangelogPage),
            _ => typeof(ProtectPage)
        });
    }

    private void Navigate(Type page)
    {
        if (ContentFrame.CurrentSourcePageType != page)
            ContentFrame.Navigate(page);
    }

    /// <summary>
    /// Navigate by nav tag from inside a page, e.g. the 调整 button on 保护项目.
    /// Selects the matching NavigationViewItem so the pane highlight follows the
    /// content instead of pointing at the page the user came from.
    /// </summary>
    public void NavigateTo(string tag)
    {
        foreach (var item in NavView.MenuItems)
        {
            if (item is NavigationViewItem entry && string.Equals(entry.Tag as string, tag, StringComparison.Ordinal))
            {
                NavView.SelectedItem = entry;
                return;
            }
        }

        // No pane item for this tag: still navigate, but there is nothing to
        // select. Falling through to a silent no-op would look like a dead button.
        Navigate(tag switch
        {
            "protect" => typeof(ProtectPage),
            "evasion" => typeof(EvasionPage),
            "inspect" => typeof(InspectPage),
            "activity" => typeof(ActivityPage),
            "changelog" => typeof(ChangelogPage),
            _ => typeof(ProtectPage)
        });
    }
}
