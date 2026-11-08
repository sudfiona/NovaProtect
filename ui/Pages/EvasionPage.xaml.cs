using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

/// <summary>
/// Evasion and environment-gate settings.
///
/// Edits are held locally and only committed when the user presses 保存设置, so a
/// half-finished tweak cannot leak into a run started from 保护项目. The
/// exception is reading: <see cref="OnNavigatedTo"/> always loads whatever is
/// currently stored, so the page can never show stale values.
/// </summary>
public sealed partial class EvasionPage : Page
{
    private bool _loading;

    /// <summary>
    /// False until the constructor has finished wiring values in.
    ///
    /// WinUI raises SelectionChanged/ValueChanged while InitializeComponent is
    /// still parsing the tree, and at that moment the sibling controls the
    /// handlers read (ProfileDescription, SeedStatusText, …) are not built yet.
    /// Letting those handlers run produced a XamlParseException that killed the
    /// window on navigation, so every handler checks this first.
    /// </summary>
    private bool _ready;

    public EvasionPage()
    {
        InitializeComponent();
        BindDetailTable();
        LoadFromSession();
        _ready = true;
    }

    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        LoadFromSession();
    }

    /// <summary>
    /// Bind the full four-profile comparison once, then only move the "current"
    /// marker in the header. Rebuilding the source per selection would be wasted
    /// work: the table content never changes, only which column is active.
    /// </summary>
    private void BindDetailTable()
    {
        ProfileDetailList.ItemsSource = EvasionProfileTable.Rows;
        RefreshDetailHeader();
    }

    private void RefreshDetailHeader()
    {
        var active = (EvasionProfile) Math.Clamp(ProfilePicker.SelectedIndex, 0, 3);
        Mark(HeadOff, "关闭", EvasionProfile.Off);
        Mark(HeadBalanced, "均衡", EvasionProfile.Balanced);
        Mark(HeadAggressive, "激进", EvasionProfile.Aggressive);
        Mark(HeadParanoid, "偏执", EvasionProfile.Paranoid);
        return;

        void Mark(TextBlock header, string label, EvasionProfile profile) =>
            header.Text = profile == active ? $"{label} · 当前" : label;
    }

    private void LoadFromSession()
    {
        _loading = true;
        try
        {
            var evasion = ProtectionSession.Evasion;
            var gate = ProtectionSession.Environment;

            ProfilePicker.SelectedIndex = (int) evasion.Profile;
            ProfileDescription.Text = EvasionProfileTable.Describe(evasion.Profile);
            ProfileBadge.Text = evasion.ProfileLabel;

            SeedBox.Text = evasion.SeedHex;
            ReseedSwitch.IsOn = evasion.Reseed;

            JunkSlider.Value = Math.Clamp(evasion.JunkDensity, 0, 8);
            AntiSandboxBox.SelectedIndex = Math.Clamp(evasion.AntiSandboxLevel, 0, 3);
            MemStreamBox.SelectedIndex = Math.Clamp(evasion.MemStreamRounds, 0, 3);
            DelaySlider.Value = Math.Clamp(evasion.DetonateDelayMs, 0, 15000);
            UnhookSwitch.IsOn = evasion.Unhook;

            KernelSlider.Value = Math.Clamp(evasion.KernelLevel, 0, 3);
            HvExitCostSwitch.IsOn = evasion.HypervisorExitCost;

            SandboxThresholdSlider.Value = Math.Clamp(gate.SandboxThreshold, 0, 100);
            EnvThresholdSlider.Value = Math.Clamp(gate.EnvThreshold, 0, 100);
            MinCpuBox.Value = gate.MinCpuCount;
            MinRamBox.Value = gate.MinRamMb;
            MinUptimeBox.Value = gate.MinUptimeMs;
            MinScreenWBox.Value = gate.MinScreenWidth;
            MinScreenHBox.Value = gate.MinScreenHeight;
            MinMonitorBox.Value = gate.MinMonitorCount;

            RefreshDetailHeader();
            RefreshLabels();
        }
        finally
        {
            _loading = false;
        }
    }

    private EvasionOptions ReadEvasion() => new()
    {
        Profile = (EvasionProfile) Math.Clamp(ProfilePicker.SelectedIndex, 0, 3),
        SeedHex = SeedBox.Text.Trim(),
        Reseed = ReseedSwitch.IsOn,
        JunkDensity = (int) Math.Round(JunkSlider.Value),
        AntiSandboxLevel = Math.Clamp(AntiSandboxBox.SelectedIndex, 0, 3),
        DetonateDelayMs = (int) Math.Round(DelaySlider.Value),
        MemStreamRounds = Math.Clamp(MemStreamBox.SelectedIndex, 0, 3),
        Unhook = UnhookSwitch.IsOn,
        KernelLevel = (int) Math.Round(KernelSlider.Value),
        HypervisorExitCost = HvExitCostSwitch.IsOn
    };

    private EnvironmentGateOptions ReadGate() => new()
    {
        SandboxThreshold = (int) Math.Round(SandboxThresholdSlider.Value),
        EnvThreshold = (int) Math.Round(EnvThresholdSlider.Value),
        MinCpuCount = ReadNumber(MinCpuBox),
        MinRamMb = ReadNumber(MinRamBox),
        MinUptimeMs = ReadNumber(MinUptimeBox),
        MinScreenWidth = ReadNumber(MinScreenWBox),
        MinScreenHeight = ReadNumber(MinScreenHBox),
        MinMonitorCount = ReadNumber(MinMonitorBox)
    };

    /// <summary>
    /// NumberBox.Value is NaN when the box is emptied, and (int) NaN is 0, which
    /// happens to be the right meaning here ("no minimum"). Clamp anyway so a
    /// typed value beyond the range cannot reach the engine.
    /// </summary>
    private static int ReadNumber(NumberBox box)
    {
        if (double.IsNaN(box.Value)) return 0;
        return (int) Math.Clamp(Math.Round(box.Value), box.Minimum, box.Maximum);
    }

    private void RefreshLabels()
    {
        JunkValue.Text = $"{(int) Math.Round(JunkSlider.Value)} / 8";
        DelayValue.Text = $"{(int) Math.Round(DelaySlider.Value)} ms";
        KernelValue.Text = $"{(int) Math.Round(KernelSlider.Value)} / 3";
        SandboxThresholdValue.Text = $"{(int) Math.Round(SandboxThresholdSlider.Value)} / 100";
        EnvThresholdValue.Text = $"{(int) Math.Round(EnvThresholdSlider.Value)} / 100";

        KernelDescription.Text = (int) Math.Round(KernelSlider.Value) switch
        {
            0 => "关闭：不生成任何内核探针，受保护程序不会触碰驱动层。",
            1 => "仅工件：释放驱动工件并做静态特征，不做运行期探测。",
            2 => "加 KUSER_SHARED_DATA tick 连续性：用不经过系统调用的时间源识别内核层插桩。",
            _ => "全开：在上一层基础上加入全部探针，包括驱动自摘链。兼容性风险最高。"
        };

        var evasion = ReadEvasion();
        var gate = ReadGate();
        ProfileBadge.Text = evasion.ProfileLabel;

        if (!evasion.HasValidSeed)
        {
            EvasionWarnBar.Severity = InfoBarSeverity.Error;
            EvasionWarnBar.Title = "种子格式无效";
            EvasionWarnBar.Message = "种子必须是 1-16 位十六进制且不等于 0。留空表示每次构建随机。";
            EvasionWarnBar.IsOpen = true;
        }
        else if (evasion.Profile == EvasionProfile.Off && (evasion.JunkDensity > 0 || evasion.AntiSandboxLevel > 0))
        {
            EvasionWarnBar.Severity = InfoBarSeverity.Warning;
            EvasionWarnBar.Title = "档位与逐项设置有冲突";
            EvasionWarnBar.Message = "规避档位为「关闭」时，引擎会先清空全部规避字段；即使在下面填了垃圾指令和反沙箱级别，本次运行仍按「关闭」处理。需要这些效果请至少选「均衡」。";
            EvasionWarnBar.IsOpen = true;
        }
        else
        {
            EvasionWarnBar.IsOpen = false;
        }

        SeedStatusText.Text = evasion.HasValidSeed
            ? (string.IsNullOrWhiteSpace(evasion.SeedHex)
                ? (evasion.Reseed ? "本次构建将从系统熵取新种子。" : "留空时引擎自身也会取熵，两次构建不会相同。")
                : $"固定种子 {evasion.SeedHex.ToLowerInvariant()}：同一输入会得到完全相同的构建，便于复现问题。")
            : "种子格式无效，保存会被拒绝。";

        GateSummaryText.Text = "当前闸门：" + gate.Summary +
            (gate.HasHardwareMinimum ? "。" : "。未设置硬件下限，只看分数阈值。");
    }

    private void ProfilePicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        ProfileDescription.Text = EvasionProfileTable.Describe((EvasionProfile) Math.Clamp(ProfilePicker.SelectedIndex, 0, 3));
        RefreshDetailHeader();
        RefreshLabels();
    }

    private void RandomSeed_Click(object sender, RoutedEventArgs e)
    {
        // 63 random bits from a 16-byte fill, so the value is always non-zero once
        // hex-encoded and stays inside the 16-digit limit the engine accepts.
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(8);
        var value = BitConverter.ToUInt64(bytes, 0) & 0x7FFF_FFFF_FFFF_FFFFUL;
        if (value == 0) value = 1;
        SeedBox.Text = value.ToString("x16").TrimStart('0');
        ReseedSwitch.IsOn = false;
        RefreshLabels();
    }

    private void CopySeed_Click(object sender, RoutedEventArgs e)
    {
        var value = SeedBox.Text.Trim();
        if (value.Length == 0)
        {
            SeedBox.Text = "先在左侧生成或填一个种子。";
            return;
        }
        var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
        package.SetText(value);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
        CopySeedButton.IsEnabled = false;
        _ = RestoreCopyButtonAsync();
    }

    private async Task RestoreCopyButtonAsync()
    {
        await Task.Delay(900);
        CopySeedButton.IsEnabled = true;
    }

    private void ReseedSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_ready || _loading) return;
        // The two are mutually exclusive in the engine: -evasion-reseed zeroes
        // the seed. Clearing the box keeps the UI from claiming both states.
        if (ReseedSwitch.IsOn) SeedBox.Text = string.Empty;
        RefreshLabels();
    }

    private void JunkSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void DelaySlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void KernelSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void SandboxThresholdSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void EnvThresholdSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void AntiSandboxBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MemStreamBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void UnhookSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void HvExitCostSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinCpuBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinRamBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinUptimeBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinScreenWBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinScreenHBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private void MinMonitorBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_ready || _loading) return;
        RefreshLabels();
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        var evasion = ReadEvasion();
        if (!evasion.HasValidSeed)
        {
            await ShowDialogAsync("种子格式无效", "种子必须是 1-16 位十六进制且不等于 0，或者留空表示每次构建随机。");
            return;
        }

        ProtectionSession.Set(evasion, ReadGate());
        await ShowDialogAsync("已保存", "对抗与规避设置已保存，保护项目页的下一次运行立即生效。");
    }

    private async void Reset_Click(object sender, RoutedEventArgs e)
    {
        ProtectionSession.Reset();
        LoadFromSession();
        await ShowDialogAsync("已恢复默认", "规避档位回到「均衡」，环境闸门回到引擎默认阈值。");
    }

    private async void RunHvAudit_Click(object sender, RoutedEventArgs e)
    {
        await RunAuditAsync("-hv-audit", "hypervisor 审计");
    }

    private async void RunKernelAudit_Click(object sender, RoutedEventArgs e)
    {
        await RunAuditAsync("-kernel-audit", "内核工件审计");
    }

    /// <summary>
    /// The audits are host probes: they read the machine and exit without a
    /// target file, so they go through the same inspection path the 检查工具 page
    /// uses (same client-invocation handshake the packer needs).
    /// </summary>
    private async Task RunAuditAsync(string flag, string label)
    {
        AuditBox.Text = $"正在执行{label}…";
        var service = new ProtectorService();
        var (ok, output) = await service.InspectAsync(string.Empty, flag);
        AuditBox.Text = ok
            ? (string.IsNullOrWhiteSpace(output) ? $"{label}完成，但没有返回内容。" : output)
            : $"{label}失败：{output}";
    }

    private async Task ShowDialogAsync(string title, string content)
    {
        // Serialized with every other notice in the app; if something already owns
        // the dialog queue the line still lands in the audit box where it is read.
        if (await DialogService.ShowAsync(XamlRoot, title, content, closeText: "好")) return;
        AuditBox.Text = $"{title}：{content}";
    }
}
