using System.Text.Json.Serialization;

namespace NovaProtect.UI.Models;

/// <summary>
/// The engine's evasion profiles. Values match the CLI's <c>-evasion</c> names
/// and its numeric aliases (off=0 … paranoid=3).
/// </summary>
public enum EvasionProfile
{
    Off = 0,
    Balanced = 1,
    Aggressive = 2,
    Paranoid = 3
}

/// <summary>
/// The evasion knobs the engine actually accepts on its command line.
///
/// Everything else in <c>EvasionConfig</c> — the static-image scrubs, loader
/// layout, memory window, presence gate, hypervisor and kernel stealth bits — has
/// no CLI override: <c>-evasion &lt;profile&gt;</c> rewrites the whole struct to
/// that profile's defaults. Offering half of them as switches would be theatre,
/// so <see cref="EvasionProfileTable"/> shows them as what the profile yields and
/// this class only carries what can really be changed.
/// </summary>
public sealed class EvasionOptions
{
    public EvasionProfile Profile { get; set; } = EvasionProfile.Balanced;

    /// <summary>
    /// Explicit 64-bit build seed as hex without a prefix. Empty means "derive
    /// from system entropy", which is what makes two builds differ.
    /// </summary>
    public string SeedHex { get; set; } = string.Empty;

    /// <summary>Draw a fresh signature for this build even though a seed is set.</summary>
    public bool Reseed { get; set; }

    /// <summary>0-8 junk blocks per injected site; 0 disables junk generation.</summary>
    public int JunkDensity { get; set; } = 2;

    /// <summary>0-3 weighted sandbox score level.</summary>
    public int AntiSandboxLevel { get; set; } = 2;

    /// <summary>Milliseconds the pre-execution gate waits before detonating (0-600000).</summary>
    public int DetonateDelayMs { get; set; } = 2500;

    /// <summary>0-3 keystream passes over encrypted regions; 0 keeps them resident.</summary>
    public int MemStreamRounds { get; set; } = 2;

    /// <summary>
    /// API unhooking. The engine takes one switch for both halves — restoring
    /// on-disk ntdll text and sweeping the IAT — so this is a single toggle here
    /// rather than two controls that would always move together.
    /// </summary>
    public bool Unhook { get; set; } = true;

    /// <summary>0 off, 1 artifacts only, 2 + tick continuity, 3 + all probes.</summary>
    public int KernelLevel { get; set; } = 2;

    /// <summary>CPUID exit-cost storm probe for hypervisor presence.</summary>
    public bool HypervisorExitCost { get; set; } = true;

    /// <summary>
    /// The engine rejects a supplied seed of zero or one that is not hex. Mirror
    /// that here so the run is refused in the UI with a readable message instead
    /// of failing inside the engine with exit code 2.
    /// </summary>
    [JsonIgnore]
    public bool HasValidSeed
    {
        get
        {
            var value = SeedHex.Trim();
            if (value.Length == 0) return true;
            if (!System.Text.RegularExpressions.Regex.IsMatch(value, "^[0-9a-fA-F]{1,16}$")) return false;
            return value.TrimStart('0').Length > 0;
        }
    }

    [JsonIgnore]
    public string ProfileLabel => Profile switch
    {
        EvasionProfile.Off => "关闭",
        EvasionProfile.Balanced => "均衡",
        EvasionProfile.Aggressive => "激进",
        _ => "偏执"
    };

    [JsonIgnore]
    public string SeedLabel => string.IsNullOrWhiteSpace(SeedHex) ? "随机（每次构建不同）" : SeedHex.Trim();

    /// <summary>
    /// The tunable detail without the profile name, because callers that show the
    /// profile next to it (the 保护项目 summary card) would otherwise print it twice.
    /// </summary>
    [JsonIgnore]
    public string Summary =>
        Profile == EvasionProfile.Off
            ? "规避已关闭：受保护程序带有正常的静态特征。"
            : $"垃圾指令 {JunkDensity}/8 · 反沙箱 {AntiSandboxLevel}/3 · 内核 {KernelLevel}/3";

    public EvasionOptions Clone() => (EvasionOptions) MemberwiseClone();
}

/// <summary>
/// Read-only view of what each profile expands to inside the engine. This is the
/// part of <c>EvasionConfig</c> that the command line cannot override, so the UI
/// shows it as information instead of pretending it is configurable.
/// </summary>
public static class EvasionProfileTable
{
    public sealed record Row(string Name, string Off, string Balanced, string Aggressive, string Paranoid)
    {
        // The comparison table puts this record in a ListView, and UIA derives the
        // item's accessible name from ToString(). The compiler-generated version
        // announces "Row { Name = ..., Off = ... }", which is noise for a screen
        // reader; spell out the four values instead.
        public override string ToString() =>
            $"{Name}：关闭 {Off}，均衡 {Balanced}，激进 {Aggressive}，偏执 {Paranoid}";
    }

    public static IReadOnlyList<Row> Rows { get; } =
    [
        new("静态特征清洗", "否", "是", "是", "是"),
        new("Rich 头 / DOS 存根", "保留", "擦除", "擦除", "擦除"),
        new("时间戳", "保留", "改写", "改写", "改写"),
        new("节区改名", "否", "是", "是", "是"),
        new("PDB 调试信息", "保留", "剥离", "剥离", "剥离"),
        new("节区松弛填充", "否", "是", "是", "是"),
        new("无效签名清理", "否", "是", "是", "是"),
        new("加载器分区布局", "否", "是", "是", "是"),
        new("禁止 RWX 页", "否", "是", "是", "是"),
        new("内存解密窗口", "全程驻留", "4096 字节", "4096 字节", "4096 字节"),
        new("用户输入闸门", "否", "是", "是", "是"),
        new("RDTSC / CPUID 时序", "否", "是", "是", "是"),
        new("hypervisor 厂商探测", "否", "是", "是", "是"),
        new("hypervisor 时间侧信道", "否", "是", "是", "是"),
        new("内核导出哈希解析", "否", "是", "是", "是"),
        new("驱动自摘链", "否", "否", "是", "是")
    ];

    public static string Describe(EvasionProfile profile) => profile switch
    {
        EvasionProfile.Off =>
            "不做任何规避。生成的程序带完整静态特征，适合本地调试或需要被安全软件正常识别的场景。",
        EvasionProfile.Balanced =>
            "默认。清洗静态特征，加入反沙箱评分、垃圾指令与内存流式解密，误报率与强度平衡。",
        EvasionProfile.Aggressive =>
            "在均衡基础上加深动态探测与驱动自摘链，适合对抗主动分析，但更容易被启发式盯上。",
        _ =>
            "最激进档位：所有探测全开、垃圾指令拉满、驱动退出时自摘。兼容性风险最高，发布前必须在目标环境实测。"
    };
}

/// <summary>
/// The environment gate. These are engine-wide <c>PackerConfig</c> fields rather
/// than evasion fields, but they only matter when the sandbox guard or the env
/// check is on, so the UI keeps them next to it.
/// </summary>
public sealed class EnvironmentGateOptions
{
    /// <summary>Block when the weighted sandbox score reaches this value (0-100).</summary>
    public int SandboxThreshold { get; set; } = 40;

    /// <summary>Block when the headless-environment score reaches this value (0-100).</summary>
    public int EnvThreshold { get; set; } = 7;

    /// <summary>Required logical processor count; 0 disables the check (1-256).</summary>
    public int MinCpuCount { get; set; }

    /// <summary>Required physical memory in MB; 0 disables the check.</summary>
    public int MinRamMb { get; set; }

    /// <summary>Required system uptime in milliseconds; 0 disables the check.</summary>
    public int MinUptimeMs { get; set; }

    /// <summary>Required primary display width; 0 disables the check.</summary>
    public int MinScreenWidth { get; set; }

    /// <summary>Required primary display height; 0 disables the check.</summary>
    public int MinScreenHeight { get; set; }

    /// <summary>Required monitor count; 0 disables the check.</summary>
    public int MinMonitorCount { get; set; }

    public EnvironmentGateOptions Clone() => (EnvironmentGateOptions) MemberwiseClone();

    [JsonIgnore]
    public bool HasHardwareMinimum =>
        MinCpuCount > 0 || MinRamMb > 0 || MinUptimeMs > 0 ||
        MinScreenWidth > 0 || MinScreenHeight > 0 || MinMonitorCount > 0;

    [JsonIgnore]
    public string Summary
    {
        get
        {
            var parts = new List<string> { $"沙箱阈值 {SandboxThreshold}", $"环境阈值 {EnvThreshold}" };
            if (MinCpuCount > 0) parts.Add($"{MinCpuCount} 核");
            if (MinRamMb > 0) parts.Add($"{MinRamMb} MB");
            if (MinUptimeMs > 0) parts.Add($"运行 {MinUptimeMs} ms");
            if (MinScreenWidth > 0 || MinScreenHeight > 0) parts.Add($"{MinScreenWidth}×{MinScreenHeight}");
            if (MinMonitorCount > 0) parts.Add($"{MinMonitorCount} 显示器");
            return string.Join(" · ", parts);
        }
    }
}
