using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace NovaProtect.UI.Pages;

public sealed partial class ProtectPage : Page
{
    private readonly ProtectorService _protector = new();
    private readonly ObservableCollection<string> _virtualFiles = [];
    private readonly ObservableCollection<ProtectionObjectRule> _markerRules = [];
    private readonly ObservableCollection<FunctionItem> _functionItems = [];
    private List<ScannedFunction> _scannedFunctions = [];
    private CancellationTokenSource? _runCancellation;
    private PeSummary? _peSummary;
    private bool _settingDefaultOutput;
    private bool _applyingPreset;
    private bool _loadingMarkerEditor;
    private string? _projectPath;

    public ProtectPage()
    {
        InitializeComponent();
        VirtualFilesList.ItemsSource = _virtualFiles;
        MarkerList.ItemsSource = _markerRules;
        FunctionList.ItemsSource = _functionItems;
        CapabilityMatrixList.ItemsSource = ProtectionPlanner.MatrixFor(null);
        var initialPreset = PresetBox.SelectedIndex;
        PresetBox.SelectedIndex = -1;
        PresetBox.SelectedIndex = initialPreset;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        InputPathBox.Focus(FocusState.Programmatic);
        // The evasion page may have been edited while this page stayed cached.
        UpdateEvasionSummary();
    }

    /// <summary>
    /// Show the effective evasion profile and gate thresholds, because both are
    /// set on another page and a user should not have to navigate away to know
    /// what this run will actually do.
    /// </summary>
    private void UpdateEvasionSummary()
    {
        var evasion = ProtectionSession.Evasion;
        var gate = ProtectionSession.Environment;
        // Off already reads as a complete sentence, so it must not get the label
        // prefixed; the other profiles need the label because Summary is detail only.
        EvasionSummaryText.Text = evasion.Profile == EvasionProfile.Off
            ? evasion.Summary
            : $"{evasion.ProfileLabel} · {evasion.Summary}";
        EnvGateSummaryText.Text = (SandboxGuardSwitch.IsOn || EnvCheckSwitch.IsOn)
            ? "环境闸门：" + gate.Summary
            : "环境闸门未启用：打开「沙箱防护」或「环境检查」后才按阈值判定。";
    }

    private void OpenEvasionPage_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is { } window) window.NavigateTo("evasion");
    }

    private nint WindowHandle => App.MainWindow?.WindowHandle ?? 0;

    private async void BrowseInput_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, WindowHandle);
        picker.FileTypeFilter.Add(".exe");
        var file = await picker.PickSingleFileAsync();
        if (file is not null) SetInputPath(file.Path);
    }

    private async void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileSavePicker { SuggestedFileName = SuggestedOutputName() };
        InitializeWithWindow.Initialize(picker, WindowHandle);
        picker.FileTypeChoices.Add("Windows 可执行文件", [".exe"]);
        var file = await picker.PickSaveFileAsync();
        if (file is not null) OutputPathBox.Text = file.Path;
    }

    private void FileCard_DragOver(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            e.AcceptedOperation = DataPackageOperation.Copy;
            e.DragUIOverride.Caption = "使用此文件作为保护目标";
            e.DragUIOverride.IsCaptionVisible = true;
        }
    }

    private async void FileCard_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        var items = await e.DataView.GetStorageItemsAsync();
        var file = items.OfType<StorageFile>().FirstOrDefault(item =>
            string.Equals(item.FileType, ".exe", StringComparison.OrdinalIgnoreCase));
        if (file is not null) SetInputPath(file.Path);
    }

    private void InputPathBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        var path = InputPathBox.Text.Trim();
        if (!File.Exists(path))
        {
            _peSummary = null;
            _markerRules.Clear();
            _scannedFunctions = [];
            _functionItems.Clear();
            FunctionScanBar.Title = "等待目标";
            FunctionScanBar.Message = "选择 x64/x86 PE 后扫描函数表（x64 读取 .pdata 异常目录）。";
            FunctionScanBar.Severity = InfoBarSeverity.Informational;
            FunctionScanBar.IsOpen = true;
            UpdateFunctionSelectionSummary();
            ArchitectureBadge.Text = "等待有效文件";
            PeInfoBar.IsOpen = false;
            UpdateMarkerEditor();
            CapabilityMatrixList.ItemsSource = ProtectionPlanner.MatrixFor(null);
            UpdateCapabilitySummary();
            return;
        }

        _peSummary = PeInspector.Inspect(path);
        ArchitectureBadge.Text = _peSummary.IsValid
            ? $"{_peSummary.Architecture} · {_peSummary.ToolchainDisplay}"
            : "无效 PE 文件";
        PeInfoBar.Severity = _peSummary.IsValid ? InfoBarSeverity.Informational : InfoBarSeverity.Error;
        PeInfoBar.Title = _peSummary.IsValid ? "已识别目标" : "无法识别目标";
        PeInfoBar.Message = _peSummary.IsValid
            ? $"{_peSummary.Architecture} · {_peSummary.Kind} · {_peSummary.ToolchainDisplay} · {FormatSize(_peSummary.Size)}。{_peSummary.Detail}"
            : _peSummary.Detail;
        PeInfoBar.IsOpen = true;
        MergeMarkerRules(_peSummary.Markers);
        CapabilityMatrixList.ItemsSource = ProtectionPlanner.MatrixFor(_peSummary);
        UpdateCapabilitySummary();

        if (!_settingDefaultOutput && string.IsNullOrWhiteSpace(OutputPathBox.Text))
        {
            _settingDefaultOutput = true;
            OutputPathBox.Text = SuggestedOutputPath(path);
            _settingDefaultOutput = false;
        }
    }

    private async void CopyMachineId_Click(object sender, RoutedEventArgs e)
    {
        var result = await _protector.InspectAsync(string.Empty, "-machineid");
        if (!result.Success)
        {
            await ShowDialogAsync("读取本机 ID 失败", result.Output, true);
            return;
        }
        var id = result.Output.Trim();
        ActivationBindingBox.Text = id;
        AppendLog($"已读取本机激活 ID：{id}（已填入激活/硬件绑定框）");
    }

    private void SetInputPath(string path)
    {
        InputPathBox.Text = path;
        _settingDefaultOutput = true;
        OutputPathBox.Text = SuggestedOutputPath(path);
        _settingDefaultOutput = false;
    }

    private void ModePicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        switch (ModePicker.SelectedIndex)
        {
            case 0:
                ModeDescription.Title = "变异模式";
                ModeDescription.Message = "对支持的 x64 代码执行等价变换，通常兼容性更高、体积增长更小。";
                ModeDescription.Severity = InfoBarSeverity.Informational;
                break;
            case 1:
                ModeDescription.Title = "虚拟化模式";
                ModeDescription.Message = "将已标记的 x64 代码区域转换为自定义 VM 字节码。";
                ModeDescription.Severity = InfoBarSeverity.Informational;
                break;
            default:
                ModeDescription.Title = "Ultra 模式";
                ModeDescription.Message = "同时启用代码变异与虚拟化，适合需要最高保护等级的 x64 程序。";
                ModeDescription.Severity = InfoBarSeverity.Success;
                break;
        }
        UpdateCapabilitySummary();
    }

    private void PresetBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ModePicker is null || MutationSlider is null || VmSlider is null ||
            AntiDebugBox is null || AntiVmBox is null || MemoryProtectionSwitch is null ||
            ImportProtectionSwitch is null || ResourceProtectionSwitch is null ||
            PackSectionsSwitch is null || StripDebugSwitch is null) return;
        if (_applyingPreset || PresetBox.SelectedItem is not ComboBoxItem { Tag: string tag }) return;
        _applyingPreset = true;
        try
        {
            switch (tag)
            {
                case "basic":
                    ModePicker.SelectedIndex = 0;
                    MutationSlider.Value = 1;
                    VmSlider.Value = 0;
                    AntiDebugBox.SelectedIndex = 0;
                    AntiVmBox.SelectedIndex = 0;
                    MemoryProtectionSwitch.IsOn = false;
                    ImportProtectionSwitch.IsOn = false;
                    ResourceProtectionSwitch.IsOn = false;
                    PackSectionsSwitch.IsOn = true;
                    StripDebugSwitch.IsOn = false;
                    break;
                case "balanced":
                    ModePicker.SelectedIndex = 1;
                    MutationSlider.Value = 2;
                    VmSlider.Value = 5;
                    AntiDebugBox.SelectedIndex = 1;
                    AntiVmBox.SelectedIndex = 0;
                    MemoryProtectionSwitch.IsOn = true;
                    ImportProtectionSwitch.IsOn = true;
                    ResourceProtectionSwitch.IsOn = false;
                    PackSectionsSwitch.IsOn = true;
                    StripDebugSwitch.IsOn = true;
                    break;
                case "high":
                    ModePicker.SelectedIndex = 2;
                    MutationSlider.Value = 3;
                    VmSlider.Value = 8;
                    AntiDebugBox.SelectedIndex = 2;
                    AntiVmBox.SelectedIndex = 1;
                    MemoryProtectionSwitch.IsOn = true;
                    ImportProtectionSwitch.IsOn = true;
                    ResourceProtectionSwitch.IsOn = true;
                    PackSectionsSwitch.IsOn = true;
                    StripDebugSwitch.IsOn = true;
                    break;
                case "ultra":
                    ModePicker.SelectedIndex = 2;
                    MutationSlider.Value = 3;
                    VmSlider.Value = 10;
                    AntiDebugBox.SelectedIndex = 3;
                    AntiVmBox.SelectedIndex = 2;
                    MemoryProtectionSwitch.IsOn = true;
                    ImportProtectionSwitch.IsOn = true;
                    ResourceProtectionSwitch.IsOn = true;
                    PackSectionsSwitch.IsOn = true;
                    StripDebugSwitch.IsOn = true;
                    break;
            }
        }
        finally
        {
            _applyingPreset = false;
            UpdateCapabilitySummary();
        }
    }

    private void MutationSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (MutationValue is null) return;
        var labels = new[] { "关闭", "轻量", "中等", "高强度" };
        var value = Math.Clamp((int)Math.Round(e.NewValue), 0, 3);
        MutationValue.Text = $"{value} · {labels[value]}";
        UpdateCapabilitySummary();
    }

    private void VmSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (VmValue is not null) VmValue.Text = $"{(int)Math.Round(e.NewValue)} / 10";
        UpdateCapabilitySummary();
    }

    private async void AddVirtualFiles_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, WindowHandle);
        picker.FileTypeFilter.Add("*");
        var files = await picker.PickMultipleFilesAsync();
        foreach (var file in files)
            if (!_virtualFiles.Contains(file.Path, StringComparer.OrdinalIgnoreCase)) _virtualFiles.Add(file.Path);
        VirtualFilesEmptyText.Visibility = _virtualFiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RemoveVirtualFiles_Click(object sender, RoutedEventArgs e)
    {
        foreach (var selected in VirtualFilesList.SelectedItems.Cast<string>().ToArray())
            _virtualFiles.Remove(selected);
        VirtualFilesEmptyText.Visibility = _virtualFiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        if (!await ValidateAsync()) return;

        var options = CollectOptions();
        var plan = ProtectionPlanner.Create(options, _peSummary);
        var planPath = await ProjectStore.SaveBuildPlanAsync(plan, "prebuild");
        if (plan.HasBlockingConflicts)
        {
            await ShowDialogAsync("构建配置存在冲突", plan.Summary, true);
            return;
        }
        SetRunning(true);
        AppendLog($"—— {DateTime.Now:yyyy-MM-dd HH:mm:ss} 开始保护 ——");
        AppendLog($"输入: {options.InputPath}");
        AppendLog($"输出: {options.OutputPath}");
        AppendLog($"规避: {options.Evasion.ProfileLabel} · {options.Evasion.Summary}");
        AppendLog(plan.Summary);
        AppendLog($"构建计划: {planPath}");
        RunStatusText.Text = "正在准备保护管线…";
        RunProgress.Value = 0;
        ProgressText.Text = "0%";
        _runCancellation = new CancellationTokenSource();

        var result = await _protector.RunAsync(options, (percent, message) =>
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                AppendLog(message);
                if (percent >= 0)
                {
                    RunProgress.Value = percent;
                    ProgressText.Text = $"{percent}%";
                    RunStatusText.Text = message;
                }
            });
        }, _runCancellation.Token);

        SetRunning(false);
        plan.Result = result.Success ? "success" : (result.ExitCode == -2 ? "cancelled" : "failed");
        plan.ExitCode = result.ExitCode;
        plan.CompletedAt = DateTimeOffset.Now;
        // Record exactly what the core was told to do. Without it, the evasion
        // profile on this plan is only a claim about the UI state at some past
        // moment, not evidence of what produced the artifact.
        plan.CommandLine = result.CommandLine;
        await ProjectStore.SaveBuildPlanAsync(plan, plan.Result ?? "completed");
        if (!string.IsNullOrWhiteSpace(result.CommandLine))
            AppendLog("命令行: " + result.CommandLine);
        if (result.Success)
        {
            RunProgress.Value = 100;
            ProgressText.Text = "100%";
            RunStatusText.Text = "保护完成";
            AppendLog("完成：已生成受保护文件。");
            ActivityStore.Add(new ActivityItem(DateTimeOffset.Now, "保护完成", Path.GetFileName(options.OutputPath), true));
            await ShowDialogAsync("保护完成", $"输出文件已生成：\n{options.OutputPath}");
        }
        else
        {
            var cancelled = result.ExitCode == -2;
            RunStatusText.Text = cancelled ? "已取消" : "保护失败";
            AppendLog(result.Summary);
            ActivityStore.Add(new ActivityItem(DateTimeOffset.Now, cancelled ? "保护已取消" : "保护失败", result.Summary, false));
            if (!cancelled) await ShowDialogAsync("保护失败", result.Summary, true);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => _runCancellation?.Cancel();

    private void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Text = string.Empty;

    // The engine arms the delayed worker from the sandbox guard by default,
    // because a start-up-only sample cannot see a monitor that attaches later.
    // The UI mirrors that so the checkbox never disagrees with the produced
    // image. Turning the guard off leaves the worker alone: an operator who
    // unticked it deliberately keeps that choice.
    private void SandboxGuardSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        if (_applyingPreset) return;
        if (SandboxGuardSwitch.IsOn) AuditRecheckSwitch.IsOn = true;
        UpdateEvasionSummary();
    }

    private void EnvCheckSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        if (_applyingPreset) return;
        UpdateEvasionSummary();
    }

    private ProtectionOptions CollectOptions()
    {
        var options = new ProtectionOptions
        {
            InputPath = InputPathBox.Text.Trim(),
            OutputPath = OutputPathBox.Text.Trim(),
            Mode = ModePicker.SelectedIndex switch
            {
                0 => ProtectionMode.Mutation,
                1 => ProtectionMode.Virtualization,
                _ => ProtectionMode.Ultra
            },
            MutationStrength = (int)Math.Round(MutationSlider.Value),
            VmComplexity = (int)Math.Round(VmSlider.Value),
            EnableRevirtualization = RevirtSwitch.IsOn,
            RevirtualizationLevel = SelectedTag(RevirtLevelBox),
            AntiDebugLevel = SelectedTag(AntiDebugBox),
            AntiVmLevel = SelectedTag(AntiVmBox),
            MemoryProtection = MemoryProtectionSwitch.IsOn,
            ImportProtection = ImportProtectionSwitch.IsOn,
            ResourceProtection = ResourceProtectionSwitch.IsOn,
            SandboxGuard = SandboxGuardSwitch.IsOn,
            AntiDump = AntiDumpSwitch.IsOn,
            EnvCheck = EnvCheckSwitch.IsOn,
            SelfIsolation = SelfIsolationSwitch.IsOn,
            AuditRecheck = AuditRecheckSwitch.IsOn,
            PackSections = PackSectionsSwitch.IsOn,
            EncryptSections = EncryptSectionsSwitch.IsOn,
            StripDebugInfo = StripDebugSwitch.IsOn,
            StripRelocations = StripRelocationsSwitch.IsOn,
            StripExports = StripExportsSwitch.IsOn,
            Watermark = WatermarkBox.Text.Trim(),
            LicenseKey = LicenseKeyBox.Password,
            ActivationBinding = ActivationBindingBox.Text.Trim(),

            // Evasion and the environment gate live on their own page because
            // they have far more controls than fit here. They are global
            // preferences rather than per-project ones, so the run reads the
            // shared session instead of keeping a second copy that could drift.
            Evasion = ProtectionSession.Evasion,
            Environment = ProtectionSession.Environment,
        };
        options.VirtualFiles.AddRange(_virtualFiles);
        options.ObjectRules.AddRange(_markerRules);
        options.ObjectRules.AddRange(CollectFunctionRules());
        return options;
    }

    private async Task<bool> ValidateAsync()
    {
        var input = InputPathBox.Text.Trim();
        var output = OutputPathBox.Text.Trim();
        if (!File.Exists(input))
        {
            await ShowDialogAsync("请选择有效文件", "输入文件不存在或无法访问。", true);
            return false;
        }
        if (_peSummary is not { IsValid: true })
        {
            await ShowDialogAsync("文件格式无效", "目标不是可识别的 Windows PE 文件。", true);
            return false;
        }
        if (_peSummary.IsDll)
        {
            await ShowDialogAsync("请选择 EXE 程序", $"NovaProtect {ProductInfo.Version} 的正式输入范围是由 C/C++、C#/VB .NET、Rust 或 Golang 生成的 EXE。", true);
            return false;
        }
        if (string.IsNullOrWhiteSpace(output))
        {
            await ShowDialogAsync("请选择输出位置", "输出文件路径不能为空。", true);
            return false;
        }
        if (string.Equals(Path.GetFullPath(input), Path.GetFullPath(output), StringComparison.OrdinalIgnoreCase))
        {
            await ShowDialogAsync("输出路径无效", "为了避免覆盖原文件，输出路径必须与输入路径不同。", true);
            return false;
        }

        var plan = ProtectionPlanner.Create(CollectOptions(), _peSummary);
        if (plan.HasBlockingConflicts)
        {
            await ShowDialogAsync("构建配置存在冲突", plan.Summary, true);
            return false;
        }

        // The evasion page refuses to save a malformed seed, but a project file
        // can carry one, and the engine aborts with exit 2 on a zero seed. Catch
        // it here so the failure names the field instead of surfacing as an
        // engine exit code halfway through a build.
        var evasion = ProtectionSession.Evasion;
        if (!evasion.HasValidSeed)
        {
            await ShowDialogAsync("构建签名种子无效",
                $"当前种子是「{evasion.SeedHex}」，不是 1-16 位十六进制或值为零。请到「对抗与规避」页重新生成，或清空让引擎自行取熵。", true);
            return false;
        }
        if (_peSummary.Architecture.Contains("x64", StringComparison.OrdinalIgnoreCase) &&
            (ModePicker.SelectedIndex != 0) && VmSlider.Value <= 0)
        {
            await ShowDialogAsync("VM 复杂度为 0", "当前模式请求虚拟化，但 VM 复杂度为 0。请提高复杂度，或切换到变异模式。", true);
            return false;
        }
        return true;
    }

    private void SetRunning(bool running)
    {
        StartButton.IsEnabled = !running;
        CancelButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        InputPathBox.IsEnabled = !running;
        OutputPathBox.IsEnabled = !running;
        if (running) EnsureLogTimer().Start();
        else
        {
            _logTimer?.Stop();
            FlushLog();
        }
    }

    // The engine reports progress per VM region, so selecting a few thousand
    // functions produced thousands of lines within a second. Writing each one
    // straight into LogBox re-lays-out the whole TextBox (it is NoWrap and
    // read-only), which is quadratic in the number of lines and froze the
    // window while the engine itself had already finished. Buffer instead and
    // flush on a timer, keeping only a rolling tail of the document.
    private const int MaxLogChars = 120_000;
    private readonly System.Text.StringBuilder _logPending = new();
    private readonly object _logGate = new();
    private DispatcherQueueTimer? _logTimer;

    private DispatcherQueueTimer EnsureLogTimer()
    {
        if (_logTimer is null)
        {
            _logTimer = DispatcherQueue.CreateTimer();
            _logTimer.Interval = TimeSpan.FromMilliseconds(120);
            _logTimer.IsRepeating = true;
            _logTimer.Tick += (_, _) => FlushLog();
        }
        return _logTimer;
    }

    private void AppendLog(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        lock (_logGate)
        {
            if (_logPending.Length > 0) _logPending.Append('\n');
            _logPending.Append(line);
        }
        // Outside a build there is no timer running; show the line immediately.
        if (_logTimer is null || !_logTimer.IsRunning) FlushLog();
    }

    private void FlushLog()
    {
        string chunk;
        lock (_logGate)
        {
            if (_logPending.Length == 0) return;
            chunk = _logPending.ToString();
            _logPending.Clear();
        }
        var combined = LogBox.Text.Length == 0 ? chunk : LogBox.Text + "\n" + chunk;
        if (combined.Length > MaxLogChars)
            combined = combined.Substring(combined.Length - MaxLogChars);
        LogBox.Text = combined;
        LogBox.SelectionStart = combined.Length;
    }

    private void UpdateCapabilitySummary()
    {
        if (ConfigSummaryText is null) return;
        ConfigSummaryText.Text = ProtectionPlanner.Create(CollectOptions(), _peSummary).Summary;
    }

    private void MergeMarkerRules(IReadOnlyList<ProtectionObjectRule> detected)
    {
        var previous = _markerRules.ToDictionary(rule => (rule.StartRva, rule.EndRva));
        _markerRules.Clear();
        foreach (var marker in detected)
        {
            if (previous.TryGetValue((marker.StartRva, marker.EndRva), out var rule)) _markerRules.Add(rule);
            else
            {
                marker.VmComplexity = (int)Math.Round(VmSlider.Value);
                marker.MutationStrength = (int)Math.Round(MutationSlider.Value);
                _markerRules.Add(marker);
            }
        }
        MarkerInfoBar.Title = _markerRules.Count == 0 ? "未发现 SDK marker" : $"发现 {_markerRules.Count} 个 SDK marker 区域";
        MarkerInfoBar.Message = _markerRules.Count == 0
            ? "对象编辑器保持为空；不会用导出、符号或反编译结果伪装成可保护对象。"
            : "对象列表直接来自 NovaProtect SDK marker 的字节模式和 RVA 边界。";
        MarkerInfoBar.Severity = _markerRules.Count == 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success;
        MarkerList.SelectedIndex = _markerRules.Count > 0 ? 0 : -1;
        UpdateMarkerEditor();
    }

    private void RescanMarkers_Click(object sender, RoutedEventArgs e)
    {
        var path = InputPathBox.Text.Trim();
        if (!File.Exists(path)) return;
        _peSummary = PeInspector.Inspect(path);
        MergeMarkerRules(_peSummary.Markers);
        CapabilityMatrixList.ItemsSource = ProtectionPlanner.MatrixFor(_peSummary);
        UpdateCapabilitySummary();
    }

    private void MarkerList_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateMarkerEditor();

    // -------------------------------------------------------- functions ----

    private void ScanFunctions_Click(object sender, RoutedEventArgs e)
    {
        ScanFunctionsInto();
        UpdateCapabilitySummary();
    }

    // Runs the scanner and repopulates the list. Previously checked rows are
    // re-matched by RVA so a rescan keeps the user's selection.
    private void ScanFunctionsInto()
    {
        var path = InputPathBox.Text.Trim();
        if (!File.Exists(path)) return;

        var previous = _functionItems
            .Where(item => item.IsSelected)
            .ToDictionary(item => item.Rva);

        var result = FunctionScanner.Scan(path);
        _scannedFunctions = result.Functions.ToList();
        _functionItems.Clear();

        if (!result.Success)
        {
            FunctionScanBar.Title = "函数扫描失败";
            FunctionScanBar.Message = result.Error;
            FunctionScanBar.Severity = InfoBarSeverity.Error;
            UpdateFunctionSelectionSummary();
            return;
        }

        foreach (var function in _scannedFunctions)
        {
            var item = new FunctionItem(function);
            if (previous.TryGetValue(function.Rva, out var kept))
            {
                item.IsSelected = true;
                item.Mode = kept.Mode;
                item.VmComplexity = kept.VmComplexity;
                item.MutationStrength = kept.MutationStrength;
                item.LockToActivation = kept.LockToActivation;
            }
            _functionItems.Add(item);
        }

        FunctionScanBar.Title = $"扫描到 {_scannedFunctions.Count} 个函数";
        FunctionScanBar.Message = $"{result.Summary}；可虚拟化 {_scannedFunctions.Count(f => f.VmFeasible)} 个。" +
                                  " VM 运行时会对无法翻译的函数自动回退原生执行。";
        FunctionScanBar.Severity = InfoBarSeverity.Success;
        RefreshFunctionList();
        UpdateFunctionSelectionSummary();
    }

    private void FunctionFilterBox_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        RefreshFunctionList();

    private void RefreshFunctionList()
    {
        if (FunctionList is null) return;
        var filter = (FunctionFilterBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "all";
        IEnumerable<FunctionItem> view = filter switch
        {
            "feasible" => _functionItems.Where(item => item.VmFeasible),
            "export" => _functionItems.Where(item => item.IsExported),
            "checked" => _functionItems.Where(item => item.IsSelected),
            _ => _functionItems
        };
        FunctionList.ItemsSource = view.ToList();
        FunctionCountText.Text = $"{view.Count()} / {_functionItems.Count}";
    }

    private void FunctionSelectAll_Click(object sender, RoutedEventArgs e) => SetFunctionSelection(true, false);

    private void FunctionInvert_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _functionItems) item.IsSelected = !item.IsSelected;
        RefreshFunctionList();
        UpdateFunctionSelectionSummary();
    }

    // "Add all functions": check every row the VM can realistically take.
    // The runtime still skips anything that fails translation, so checking
    // everything is safe - it just widens coverage.
    private void FunctionAddAll_Click(object sender, RoutedEventArgs e) => SetFunctionSelection(true, true);

    private void FunctionClear_Click(object sender, RoutedEventArgs e) => SetFunctionSelection(false, false);

    private void SetFunctionSelection(bool selected, bool feasibleOnly)
    {
        foreach (var item in _functionItems)
        {
            if (feasibleOnly && !item.VmFeasible) continue;
            item.IsSelected = selected;
        }
        RefreshFunctionList();
        UpdateFunctionSelectionSummary();
    }

    private void FunctionApplyBatch_Click(object sender, RoutedEventArgs e)
    {
        var tag = (FunctionBatchModeBox.SelectedItem as ComboBoxItem)?.Tag as string;
        MarkerProtectionMode mode;
        if (tag == "skip") mode = MarkerProtectionMode.Skip;
        else if (tag == "virtualization") mode = MarkerProtectionMode.Virtualization;
        else if (tag == "ultra") mode = MarkerProtectionMode.Ultra;
        else mode = MarkerProtectionMode.Inherit;
        var vm = double.IsNaN(FunctionBatchVmBox.Value) ? 6 : (int)Math.Clamp(FunctionBatchVmBox.Value, 0, 10);
        var mutation = double.IsNaN(FunctionBatchMutationBox.Value) ? 2 : (int)Math.Clamp(FunctionBatchMutationBox.Value, 0, 3);
        var lockToActivation = FunctionBatchActivationSwitch.IsOn;

        var applied = 0;
        foreach (var item in _functionItems.Where(item => item.IsSelected))
        {
            item.Mode = mode;
            item.VmComplexity = vm;
            item.MutationStrength = mutation;
            item.LockToActivation = lockToActivation;
            applied++;
        }
        AppendLog(applied == 0
            ? "批量应用：没有勾选的函数。"
            : $"批量应用：已更新 {applied} 个勾选函数的保护参数。");
        UpdateFunctionSelectionSummary();
        UpdateCapabilitySummary();
    }

    private void UpdateFunctionSelectionSummary()
    {
        if (FunctionSelectionSummary is null) return;
        var selected = _functionItems.Where(item => item.IsSelected).ToList();
        if (selected.Count == 0)
        {
            FunctionSelectionSummary.Text = "尚未勾选函数。函数级保护与 SDK marker 区域可同时使用。";
            return;
        }
        var feasible = selected.Count(item => item.VmFeasible);
        var bytes = selected.Sum(item => (long)item.Size);
        FunctionSelectionSummary.Text =
            $"已勾选 {selected.Count} 个函数（其中 {feasible} 个满足 VM 前置条件），合计 {FormatSize(bytes)}。" +
            (feasible < selected.Count
                ? " 含栈帧或过小的函数会由 VM 运行时自动跳过并保持原生执行。"
                : string.Empty);
    }

    private List<ProtectionObjectRule> CollectFunctionRules() =>
        _functionItems.Where(item => item.IsSelected).Select(item => item.ToRule()).ToList();

    // A saved project carries the checked functions as rules; re-scan the
    // input and re-apply the selection so a reload round-trips exactly.
    private void RestoreFunctionSelection(IReadOnlyList<ProtectionObjectRule> rules)
    {
        var functionRules = rules
            .Where(rule => string.Equals(rule.Source, ProductInfo.FunctionSource, StringComparison.Ordinal))
            .ToList();
        if (functionRules.Count == 0)
        {
            if (_scannedFunctions.Count == 0)
            {
                _functionItems.Clear();
                UpdateFunctionSelectionSummary();
            }
            return;
        }

        ScanFunctionsInto();
        foreach (var saved in functionRules)
        {
            var item = _functionItems.FirstOrDefault(candidate => candidate.Rva == saved.StartRva);
            if (item is null) continue;
            item.IsSelected = true;
            item.Mode = saved.Mode;
            item.VmComplexity = saved.VmComplexity;
            item.MutationStrength = saved.MutationStrength;
            item.LockToActivation = saved.LockToActivation;
        }
        RefreshFunctionList();
        UpdateFunctionSelectionSummary();
    }

    private void UpdateMarkerEditor()
    {
        if (MarkerNameBox is null) return;
        _loadingMarkerEditor = true;
        try
        {
            var selected = MarkerList.SelectedItem as ProtectionObjectRule;
            var enabled = selected is not null;
            MarkerNameBox.IsEnabled = enabled;
            MarkerModeBox.IsEnabled = enabled;
            MarkerVmBox.IsEnabled = enabled;
            MarkerMutationBox.IsEnabled = enabled;
            MarkerActivationSwitch.IsEnabled = enabled;
            MarkerNameBox.Text = selected?.Name ?? string.Empty;
            MarkerModeBox.SelectedIndex = selected?.Mode switch
            {
                MarkerProtectionMode.Skip => 1,
                MarkerProtectionMode.Virtualization => 2,
                MarkerProtectionMode.Ultra => 3,
                _ => 0
            };
            MarkerVmBox.Value = selected?.VmComplexity ?? 0;
            MarkerMutationBox.Value = selected?.MutationStrength ?? 0;
            MarkerActivationSwitch.IsOn = selected?.LockToActivation ?? false;
            MarkerRangeText.Text = selected is null ? string.Empty :
                $"来源 {selected.Provenance}；marker RVA 0x{selected.MarkerRva:X8}；区域 {selected.AddressRange}；{selected.Size} 字节";
        }
        finally { _loadingMarkerEditor = false; }
    }

    private void MarkerEditor_Changed(object sender, object e) => ApplyMarkerEditor();
    private void MarkerEditor_NumberChanged(NumberBox sender, NumberBoxValueChangedEventArgs e) => ApplyMarkerEditor();
    private void MarkerEditor_Toggled(object sender, RoutedEventArgs e) => ApplyMarkerEditor();

    private void ApplyMarkerEditor()
    {
        if (_loadingMarkerEditor || MarkerList.SelectedItem is not ProtectionObjectRule selected) return;
        selected.Name = string.IsNullOrWhiteSpace(MarkerNameBox.Text) ? selected.Id : MarkerNameBox.Text.Trim();
        selected.Mode = MarkerModeBox.SelectedIndex switch
        {
            1 => MarkerProtectionMode.Skip,
            2 => MarkerProtectionMode.Virtualization,
            3 => MarkerProtectionMode.Ultra,
            _ => MarkerProtectionMode.Inherit
        };
        selected.VmComplexity = double.IsNaN(MarkerVmBox.Value) ? 0 : Math.Clamp((int)MarkerVmBox.Value, 0, 10);
        selected.MutationStrength = double.IsNaN(MarkerMutationBox.Value) ? 0 : Math.Clamp((int)MarkerMutationBox.Value, 0, 3);
        selected.LockToActivation = MarkerActivationSwitch.IsOn;
        var index = MarkerList.SelectedIndex;
        MarkerList.ItemsSource = null;
        MarkerList.ItemsSource = _markerRules;
        MarkerList.SelectedIndex = index;
        UpdateCapabilitySummary();
    }

    private async void SaveProject_Click(object sender, RoutedEventArgs e) => await SaveProjectAsync(false);
    private async void ExportProject_Click(object sender, RoutedEventArgs e) => await SaveProjectAsync(true);

    private async Task SaveProjectAsync(bool forcePicker)
    {
        var path = forcePicker ? null : _projectPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            var picker = new FileSavePicker { SuggestedFileName = Path.GetFileNameWithoutExtension(SuggestedOutputName()) };
            InitializeWithWindow.Initialize(picker, WindowHandle);
            picker.FileTypeChoices.Add("NovaProtect 项目", [".novaprotect.json"]);
            var file = await picker.PickSaveFileAsync();
            if (file is null) return;
            path = file.Path;
        }
        await ProjectStore.SaveProjectAsync(path, CollectOptions());
        _projectPath = path;
        AppendLog($"项目已保存: {path}");
    }

    private async void LoadProject_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, WindowHandle);
        picker.FileTypeFilter.Add(".json");
        var file = await picker.PickSingleFileAsync();
        if (file is null) return;
        try
        {
            var project = await ProjectStore.LoadProjectAsync(file.Path);
            ApplyOptions(project.Options);
            _projectPath = file.Path;
            AppendLog($"项目已导入: {file.Path}");
        }
        catch (Exception ex) { await ShowDialogAsync("项目导入失败", ex.Message, true); }
    }

    private async void ExportBuildPlan_Click(object sender, RoutedEventArgs e)
    {
        var path = await ProjectStore.SaveBuildPlanAsync(ProtectionPlanner.Create(CollectOptions(), _peSummary), "manual");
        AppendLog($"构建计划已导出: {path}");
    }

    private void ApplyOptions(ProtectionOptions options)
    {
        _applyingPreset = true;
        try
        {
            SetInputPath(options.InputPath);
            OutputPathBox.Text = options.OutputPath;
            ModePicker.SelectedIndex = options.Mode switch { ProtectionMode.Mutation => 0, ProtectionMode.Virtualization => 1, _ => 2 };
            MutationSlider.Value = options.MutationStrength;
            VmSlider.Value = options.VmComplexity;
            RevirtSwitch.IsOn = options.EnableRevirtualization;
            SelectTag(RevirtLevelBox, options.RevirtualizationLevel);
            SelectTag(AntiDebugBox, options.AntiDebugLevel);
            SelectTag(AntiVmBox, options.AntiVmLevel);
            MemoryProtectionSwitch.IsOn = options.MemoryProtection;
            ImportProtectionSwitch.IsOn = options.ImportProtection;
            ResourceProtectionSwitch.IsOn = options.ResourceProtection;
            SandboxGuardSwitch.IsOn = options.SandboxGuard;
            AntiDumpSwitch.IsOn = options.AntiDump;
            EnvCheckSwitch.IsOn = options.EnvCheck;
            SelfIsolationSwitch.IsOn = options.SelfIsolation;
            AuditRecheckSwitch.IsOn = options.AuditRecheck;
            PackSectionsSwitch.IsOn = options.PackSections;
            EncryptSectionsSwitch.IsOn = options.EncryptSections;
            StripDebugSwitch.IsOn = options.StripDebugInfo;
            StripRelocationsSwitch.IsOn = options.StripRelocations;
            StripExportsSwitch.IsOn = options.StripExports;
            WatermarkBox.Text = options.Watermark;
            LicenseKeyBox.Password = options.LicenseKey;
            ActivationBindingBox.Text = options.ActivationBinding;

            // A project file records the evasion settings it was built with, so
            // opening it restores those too. This also refreshes the shared
            // session, which is what the summary card and the next run read.
            ProtectionSession.Set(options.Evasion, options.Environment);
            UpdateEvasionSummary();

            _virtualFiles.Clear();
            foreach (var item in options.VirtualFiles) _virtualFiles.Add(item);
            MergeMarkerRules(_peSummary?.Markers ?? []);
            var saved = options.ObjectRules
                .GroupBy(rule => (rule.StartRva, rule.EndRva))
                .ToDictionary(group => group.Key, group => group.First());
            for (var i = 0; i < _markerRules.Count; i++)
                if (saved.TryGetValue((_markerRules[i].StartRva, _markerRules[i].EndRva), out var rule)) _markerRules[i] = rule;
            RestoreFunctionSelection(options.ObjectRules);
            VirtualFilesEmptyText.Visibility = _virtualFiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        finally { _applyingPreset = false; UpdateMarkerEditor(); UpdateCapabilitySummary(); }
    }

    /// <summary>
    /// All notices go through <see cref="DialogService"/>, which serializes them.
    /// When something else already owns the dialog queue the text would otherwise
    /// vanish, so it is appended to the build log as a fallback.
    /// </summary>
    private async Task ShowDialogAsync(string title, string content, bool error = false)
    {
        if (await DialogService.ShowAsync(XamlRoot, title, content, error)) return;
        AppendLog($"{title}：{content}");
    }

    private static int SelectedTag(ComboBox box) =>
        box.SelectedItem is ComboBoxItem { Tag: string tag } && int.TryParse(tag, out var value) ? value : 0;

    private static void SelectTag(ComboBox box, int value)
    {
        foreach (var item in box.Items)
        {
            if (item is ComboBoxItem { Tag: string tag }
                && int.TryParse(tag, out var candidate)
                && candidate == value)
            {
                box.SelectedItem = item;
                return;
            }
        }

        box.SelectedIndex = 0;
    }

    private string SuggestedOutputName()
    {
        var input = InputPathBox.Text.Trim();
        return string.IsNullOrWhiteSpace(input) ? "protected.exe" : Path.GetFileName(SuggestedOutputPath(input));
    }

    private static string SuggestedOutputPath(string input)
    {
        var directory = Path.GetDirectoryName(input) ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(input);
        var extension = Path.GetExtension(input);
        return Path.Combine(directory, $"{name}_protected{extension}");
    }

    private static string FormatSize(long size) => size switch
    {
        >= 1024 * 1024 => $"{size / 1024d / 1024d:F1} MB",
        >= 1024 => $"{size / 1024d:F1} KB",
        _ => $"{size} B"
    };
}

