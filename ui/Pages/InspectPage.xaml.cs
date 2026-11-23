using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using NovaProtect.UI.Services;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace NovaProtect.UI.Pages;

public sealed partial class InspectPage : Page
{
    private readonly ProtectorService _service = new();
    private string _statusSource = string.Empty;
    private string _statusRendered = string.Empty;

    public InspectPage()
    {
        InitializeComponent();
        // The inspected path and its last report are page state; without the
        // cache every visit started from an empty box.
        NavigationCacheMode = NavigationCacheMode.Required;
        Localizer.Attach(this, ReapplyStatus);
    }

    /// <summary>
    /// Show a placeholder while a tool runs. The result box is out of the walker's
    /// reach — it rewrites headers and placeholders, never a TextBox body, which is
    /// where streamed tool output has to land — so the status is translated here.
    /// "请选择有效文件。" stays on screen until the user fixes the path, so it also
    /// has to be re-rendered on a language change instead of being left behind.
    /// </summary>
    private void SetStatus(string source)
    {
        _statusSource = source;
        _statusRendered = Localizer.T(source);
        ResultBox.Text = _statusRendered;
    }

    private void ReapplyStatus()
    {
        if (_statusSource.Length == 0) return;
        // A tool dump owns the box now; leave its verbatim text alone.
        if (!string.Equals(ResultBox.Text, _statusRendered, StringComparison.Ordinal)) return;
        _statusRendered = Localizer.T(_statusSource);
        ResultBox.Text = _statusRendered;
    }

    /// <summary>Hand the box over to tool output, which is shown untranslated.</summary>
    private void ShowDump(string output)
    {
        _statusSource = string.Empty;
        _statusRendered = string.Empty;
        ResultBox.Text = LogText.Tail(output, LogText.DumpLines);
    }

    private async void Browse_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, App.MainWindow?.WindowHandle ?? 0);
        picker.FileTypeFilter.Add(".exe");
        picker.FileTypeFilter.Add(".dll");
        var file = await picker.PickSingleFileAsync();
        if (file is not null) PathBox.Text = file.Path;
    }

    private async void PeInfo_Click(object sender, RoutedEventArgs e) => await RunAsync("-info");
    private async void Watermark_Click(object sender, RoutedEventArgs e) => await RunAsync("-showwatermark");
    private async void VirtualFiles_Click(object sender, RoutedEventArgs e) => await RunAsync("-listvf");

    private async void MachineId_Click(object sender, RoutedEventArgs e)
    {
        SetStatus("正在读取…");
        var result = await _service.InspectAsync(string.Empty, "-machineid");
        ShowDump(result.Output);
    }

    private async Task RunAsync(params string[] args)
    {
        var path = PathBox.Text.Trim();
        if (!File.Exists(path))
        {
            SetStatus("请选择有效文件。");
            return;
        }
        SetStatus("正在检查…");
        var result = await _service.InspectAsync(path, args);
        ShowDump(result.Output);
    }
}
