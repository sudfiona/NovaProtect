using System.Text.Json.Serialization;
using NovaProtect.UI.Services;

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
        EvasionProfile.Off => Localizer.T("关闭"),
        EvasionProfile.Balanced => Localizer.T("均衡"),
        EvasionProfile.Aggressive => Localizer.T("激进"),
        _ => Localizer.T("偏执")
    };

    [JsonIgnore]
    public string SeedLabel => string.IsNullOrWhiteSpace(SeedHex) ? Localizer.T("随机（每次构建不同）") : SeedHex.Trim();

    /// <summary>
    /// The tunable detail without the profile name, because callers that show the
    /// profile next to it (the 保护项目 summary card) would otherwise print it twice.
    /// </summary>
    [JsonIgnore]
    public string Summary =>
        Profile == EvasionProfile.Off
            ? Localizer.T("规避已关闭：受保护程序带有正常的静态特征。")
            : Localizer.F("垃圾指令 {0}/8 · 反沙箱 {1}/3 · 内核 {2}/3",
                JunkDensity, AntiSandboxLevel, KernelLevel);

    public EvasionOptions Clone() => (EvasionOptions) MemberwiseClone();
}

/// <summary>
/// Read-only view of what each profile expands to inside the engine. This is the
/// part of <c>EvasionConfig</c> that the command line cannot override, so the UI
/// shows it as information instead of pretending it is configurable.
/// </summary>
public static class EvasionProfileTable
{
    /// <summary>
    /// One comparison row. The positional parameters hold the Chinese source
    /// text, because <see cref="Rows"/> is a static table built once at type
    /// initialisation: storing translated text there would freeze whatever
    /// language happened to be active when the class was first touched. The
    /// display properties translate on read instead, so moving the language and
    /// re-binding the list is enough to re-render the table.
    /// </summary>
    public sealed record Row(
        string NameSource,
        string OffSource,
        string BalancedSource,
        string AggressiveSource,
        string ParanoidSource)
    {
        public string Name => Localizer.T(NameSource);
        public string Off => Localizer.T(OffSource);
        public string Balanced => Localizer.T(BalancedSource);
        public string Aggressive => Localizer.T(AggressiveSource);
        public string Paranoid => Localizer.T(ParanoidSource);

        // The comparison table puts this record in a ListView, and UIA derives the
        // item's accessible name from ToString(). The compiler-generated version
        // announces "Row { NameSource = ..., OffSource = ... }", which is noise for
        // a screen reader; spell out the four values instead.
        public override string ToString() =>
            Localizer.F("{0}：关闭 {1}，均衡 {2}，激进 {3}，偏执 {4}",
                Name, Off, Balanced, Aggressive, Paranoid);
    }

    // Ordered by what actually separates the three tiers: the intensity knobs come
    // first, the stages every non-off profile runs come last. The previous order
    // listed fifteen rows that read identically across 均衡 / 激进 / 偏执, so the
    // table answered "how do these differ?" with a wall of 是 — and two of the
    // rows were factually wrong (驱动自摘链 is 偏执-only, the 偏执 window is 2048).
    public static IReadOnlyList<Row> Rows { get; } =
    [
        new("垃圾指令密度", "0", "1 / 8", "3 / 8", "5 / 8"),
        new("反沙箱评分级别", "关", "1 / 3", "2 / 3", "3 / 3"),
        new("反调试级别", "关", "1 / 3", "2 / 3", "3 / 3"),
        new("内核探针级别", "关", "1 / 3", "2 / 3", "3 / 3"),
        new("预执行延迟", "0", "1500 ms", "3000 ms", "5000 ms"),
        new("内存流式解密轮数", "常驻", "1 轮", "2 轮", "3 轮"),
        new("单次解密窗口", "全程驻留", "4096 B", "4096 B", "2048 B"),
        new("CPUID 退出成本探测", "否", "否", "是", "是"),
        new("IAT 钩子扫描", "否", "否", "是", "是"),
        new("诱饵字符串", "否", "否", "是", "是"),
        new("驱动自摘链", "否", "否", "否", "是"),
        new("预置拦截阈值（可覆盖）", "—", "40", "40", "30"),
        new("静态特征清洗（Rich / 时间戳 / 节区名 / PDB / 填充 / 签名）", "否", "是", "是", "是"),
        new("加载器分区布局 · 禁止 RWX 页", "否", "是", "是", "是"),
        new("用户输入闸门 · RDTSC/CPUID 时序", "否", "是", "是", "是"),
        new("hypervisor 厂商探测 · 时间侧信道", "否", "是", "是", "是"),
        new("ntdll 文本还原 · 内核导出哈希解析", "否", "是", "是", "是")
    ];

    public static string Describe(EvasionProfile profile) => Localizer.T(profile switch
    {
        EvasionProfile.Off =>
            "不做任何规避。生成的程序带完整静态特征，适合本地调试或需要被安全软件正常识别的场景。",
        EvasionProfile.Balanced =>
            "轻档：只做静态清洗 + 单层动态探测。垃圾指令 1/8、反沙箱 1 级、延迟 1.5 s、内存解密 1 轮、内核仅工件。不启用 CPUID 退出成本与 IAT 钩子扫描——兼容性优先。",
        EvasionProfile.Aggressive =>
            "中档：在均衡之上把每项探测加深一档。垃圾指令 3/8、反沙箱与反调试各 2 级、延迟 3 s、内存解密 2 轮、内核 2 级，并新增 CPUID 退出成本探测、IAT 钩子扫描与诱饵字符串。",
        _ =>
            "重档：各项拉到引擎上限。垃圾指令 5/8、反沙箱与反调试各 3 级、延迟 5 s、内存解密 3 轮且窗口缩到 2048 B、内核 3 级并启用驱动自摘链，预置拦截阈值同时收紧到 30。兼容性风险最高，发布前必须在目标环境实测。"
    });
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
            var parts = new List<string>
            {
                Localizer.F("沙箱阈值 {0}", SandboxThreshold),
                Localizer.F("环境阈值 {0}", EnvThreshold)
            };
            if (MinCpuCount > 0) parts.Add(Localizer.F("{0} 核", MinCpuCount));
            if (MinRamMb > 0) parts.Add($"{MinRamMb} MB");
            if (MinUptimeMs > 0) parts.Add(Localizer.F("运行 {0} ms", MinUptimeMs));
            if (MinScreenWidth > 0 || MinScreenHeight > 0) parts.Add($"{MinScreenWidth}×{MinScreenHeight}");
            if (MinMonitorCount > 0) parts.Add(Localizer.F("{0} 显示器", MinMonitorCount));
            return string.Join(" · ", parts);
        }
    }
}
