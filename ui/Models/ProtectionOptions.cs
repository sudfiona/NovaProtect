using System.Text.Json.Serialization;

namespace NovaProtect.UI.Models;

public enum ProtectionMode
{
    Mutation,
    Virtualization,
    Ultra
}

public enum ProtectionTargetArchitecture
{
    Unknown,
    X86,
    X64,
    Arm64
}

public enum MarkerProtectionMode
{
    Inherit,
    Skip,
    Virtualization,
    Mutation,
    Ultra
}

public enum CapabilityState
{
    Supported,
    Partial,
    Unsupported,
    Conflict
}

public enum ExecutableToolchain
{
    Unknown,
    Cpp,
    DotNet,
    Rust,
    Go
}

public sealed class ProtectionObjectRule
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Source { get; set; } = ProductInfo.MarkerSource;
    public string DetectorVersion { get; set; } = ProductInfo.MarkerDetectorVersion;
    public uint MarkerRva { get; set; }
    public uint StartRva { get; set; }
    public uint EndRva { get; set; }
    public MarkerProtectionMode Mode { get; set; } = MarkerProtectionMode.Inherit;
    public int VmComplexity { get; set; } = 6;
    public int MutationStrength { get; set; } = 2;
    public bool LockToActivation { get; set; }

    [JsonIgnore]
    public uint Size => EndRva > StartRva ? EndRva - StartRva : 0;

    [JsonIgnore]
    public string AddressRange => $"0x{StartRva:X8} – 0x{EndRva:X8}";

    [JsonIgnore]
    public string Summary => $"{Name} · {AddressRange} · {Size} 字节";

    [JsonIgnore]
    public string Provenance => $"{Source} · {DetectorVersion}";
}

public sealed class ProtectionOptions
{
    public string InputPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = string.Empty;
    public ProtectionMode Mode { get; set; } = ProtectionMode.Ultra;
    public int MutationStrength { get; set; } = 2;
    public int VmComplexity { get; set; } = 6;
    /// <summary>
    /// Themida-style second-level virtualization. Each virtualized region is
    /// split into stages with independent opcode permutations and keys, and its
    /// straight-line arithmetic runs execute in a separate guest interpreter
    /// with a permuted register file.
    /// </summary>
    public bool EnableRevirtualization { get; set; } = true;
    /// <summary>
    /// Requested nesting level, 0-4. Level 0 is equivalent to disabling the
    /// feature; level 1 is what the engine currently implements. Higher values
    /// are accepted and reported rather than silently treated as level 1.
    /// </summary>
    public int RevirtualizationLevel { get; set; } = 1;
    public int AntiDebugLevel { get; set; } = 2;
    public int AntiVmLevel { get; set; }
    public bool MemoryProtection { get; set; }
    public bool SandboxGuard { get; set; }
    public bool AntiDump { get; set; }
    public bool EnvCheck { get; set; }
    /// <summary>
    /// Process self-isolation: after the environment gates pass, the runtime
    /// replaces its own process DACL with an empty one (denying every new
    /// OpenProcess for VM_READ and handle duplication), hides its threads from
    /// debuggers and disables extension-point injection. The protected program
    /// keeps running normally; other tools can no longer read its memory.
    /// </summary>
    public bool SelfIsolation { get; set; }
    /// <summary>
    /// Delayed re-audit: a worker re-checks module and handle baselines every
    /// minute, so a monitor that attaches after startup is still caught.
    /// </summary>
    public bool AuditRecheck { get; set; }
    public bool ImportProtection { get; set; }
    public bool ResourceProtection { get; set; }
    public bool PackSections { get; set; } = true;
    public bool EncryptSections { get; set; } = true;
    public bool StripDebugInfo { get; set; } = true;
    public bool StripRelocations { get; set; }
    public bool StripExports { get; set; }
    public string Watermark { get; set; } = string.Empty;
    public string LicenseKey { get; set; } = string.Empty;
    public string ActivationBinding { get; set; } = string.Empty;
    public List<string> VirtualFiles { get; set; } = [];
    public List<ProtectionObjectRule> ObjectRules { get; set; } = [];

    /// <summary>
    /// Static/dynamic evasion and hypervisor/driver probes. Defaults are the
    /// engine's balanced profile, so leaving this alone matches a bare CLI run.
    /// </summary>
    public EvasionOptions Evasion { get; set; } = new();

    /// <summary>
    /// Sandbox and headless-environment gate thresholds. Only consulted when
    /// <see cref="SandboxGuard"/> or <see cref="EnvCheck"/> is enabled.
    /// </summary>
    public EnvironmentGateOptions Environment { get; set; } = new();
}

public sealed class ProtectionProject
{
    public int SchemaVersion { get; set; } = ProductInfo.ProjectSchemaVersion;
    public string Product { get; set; } = ProductInfo.Name;
    public string ProductVersion { get; set; } = ProductInfo.Version;
    public DateTimeOffset SavedAt { get; set; } = DateTimeOffset.Now;
    public ProtectionOptions Options { get; set; } = new();
}

public sealed class BuildPlan
{
    public int SchemaVersion { get; set; } = ProductInfo.BuildPlanSchemaVersion;
    public string PlanId { get; set; } = Guid.NewGuid().ToString("N");
    public string Stage { get; set; } = "draft";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? PersistedAt { get; set; }
    public string InputPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Toolchain { get; set; } = string.Empty;
    public List<string> Requested { get; set; } = [];
    public List<string> Effective { get; set; } = [];
    public List<string> Skipped { get; set; } = [];
    public List<string> Conflicts { get; set; } = [];
    public List<ProtectionObjectRule> ObjectRules { get; set; } = [];

    /// <summary>
    /// The evasion settings this plan was built with, plus the exact engine
    /// arguments. Both exist so a build can be audited after the fact: the
    /// 对抗与规避 page can change the profile between runs, and without a record
    /// there is no way to tell which profile produced an existing artifact.
    /// </summary>
    public EvasionOptions? Evasion { get; set; }

    public EnvironmentGateOptions? Environment { get; set; }

    /// <summary>Full command line handed to the protection core.</summary>
    public string? CommandLine { get; set; }

    public string? Result { get; set; }
    public int? ExitCode { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    [JsonIgnore]
    public bool HasBlockingConflicts => Conflicts.Count > 0;

    [JsonIgnore]
    public string Summary =>
        $"requested: {Join(Requested)}。effective: {Join(Effective)}。" +
        $"skipped: {Join(Skipped)}。conflicts: {Join(Conflicts)}。";

    private static string Join(List<string> values) => values.Count == 0 ? "无" : string.Join("、", values);
}

public sealed record CapabilityCell(string Name, CapabilityState State, string Detail);


public sealed record PeSummary(
    bool IsValid,
    ProtectionTargetArchitecture TargetArchitecture,
    string Architecture,
    string Kind,
    bool IsManaged,
    bool IsDll,
    ExecutableToolchain Toolchain,
    string ToolchainDisplay,
    long Size,
    string Detail,
    IReadOnlyList<ProtectionObjectRule> Markers);

/// <summary>
/// The outcome of one protection run. <paramref name="CommandLine"/> carries the
/// arguments that were actually handed to the core so a build plan can record
/// them; it is null when the process never started.
/// </summary>
public sealed record ProtectionRunResult(bool Success, int ExitCode, string Summary, string? CommandLine = null);

public sealed record ActivityItem(DateTimeOffset Time, string Title, string Detail, bool Success);

public static class ProductInfo
{
    public const string Name = "NovaProtect";
    public const string WebsiteUrl = "https://nova.fbi.plus";
    // Client releases are published on GitHub; the updater reads that repository
    // directly instead of the website API.
    public const string GitHubRepository = "sudfiona/NovaProtect";
    public const string GitHubRepositoryUrl = "https://github.com/sudfiona/NovaProtect";
    public const string GitHubReleasesUrl = "https://github.com/sudfiona/NovaProtect/releases";
    public const string GitHubLatestReleaseUrl = "https://github.com/sudfiona/NovaProtect/releases/latest";
    public const string GitHubApiBase = "https://api.github.com";
    public const string GitHubDownloadHost = "github.com";
    public const string GitHubObjectHost = "objects.githubusercontent.com";
    public static string Version { get; } = ResolveVersion();
    // 3 added Evasion and Environment to ProtectionOptions. Bumping it keeps an
    // older reader from silently dropping those blocks when it round-trips a
    // project it does not fully understand.
    public const int ProjectSchemaVersion = 3;
    public const int BuildPlanSchemaVersion = 2;
    public const string MarkerSource = "NovaProtect SDK marker";
    public const string MarkerDetectorVersion = "novaprotect-sdk-marker-v1";
    public const string FunctionSource = "PE 函数扫描";
    public const string FunctionDetectorVersion = "novaprotect-function-scan-v1";

    private static string ResolveVersion()
    {
        var version = typeof(ProductInfo).Assembly.GetName().Version;
        return version is null ? "0.0.0" : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }
}

