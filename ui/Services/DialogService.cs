using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NovaProtect.UI.Services;

/// <summary>
/// Serialized ContentDialog helper.
///
/// WinUI permits a single ContentDialog per XamlRoot. A second one raised while
/// the first is still open throws a COMException out of ShowAsync, and because
/// that call is not awaited by a catch handler in most call sites it takes the
/// whole window down. Two paths reach that state in normal use: a double-click on
/// a button that raises a dialog, and a background completion racing a
/// validation prompt.
///
/// Rather than teach every caller to defend itself, all dialogs go through one
/// gate here: the second caller waits for the first to close.
/// </summary>
public static class DialogService
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    /// <summary>
    /// Show a modal notice. Returns false when a dialog owned by something else
    /// was open, so the caller can fall back to an inline surface (a log line, an
    /// InfoBar) instead of losing the message.
    /// </summary>
    public static async Task<bool> ShowAsync(XamlRoot root, string title, string content,
        bool error = false, string closeText = "确定")
    {
        if (root is null) return false;

        var panel = new StackPanel { Spacing = 10 };
        if (error)
            panel.Children.Add(new InfoBar
            {
                IsOpen = true,
                IsClosable = false,
                Severity = InfoBarSeverity.Error,
                Message = content
            });
        else
            panel.Children.Add(new TextBlock { Text = content, TextWrapping = TextWrapping.Wrap });

        await Gate.WaitAsync();
        try
        {
            await new ContentDialog
            {
                XamlRoot = root,
                Title = title,
                Content = panel,
                CloseButtonText = closeText,
                DefaultButton = ContentDialogButton.Close
            }.ShowAsync();
            return true;
        }
        catch (COMException)
        {
            // Something else owns the dialog queue on this root. Reporting failure
            // lets the caller keep the text visible somewhere it can be read.
            return false;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>Ask a yes/no question. Returns true only on explicit confirmation.</summary>
    public static async Task<bool> ConfirmAsync(XamlRoot root, string title, string content,
        string confirmText, string cancelText = "取消")
    {
        if (root is null) return false;

        await Gate.WaitAsync();
        try
        {
            var dialog = new ContentDialog
            {
                XamlRoot = root,
                Title = title,
                Content = new TextBlock { Text = content, TextWrapping = TextWrapping.Wrap },
                PrimaryButtonText = confirmText,
                CloseButtonText = cancelText,
                DefaultButton = ContentDialogButton.Close
            };
            return await dialog.ShowAsync() == ContentDialogResult.Primary;
        }
        catch (COMException)
        {
            return false;
        }
        finally
        {
            Gate.Release();
        }
    }
}
