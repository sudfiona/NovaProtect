using System.Buffers.Binary;
using System.Text.Json;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static ProtectionObjectRule CopyRule(ProtectionObjectRule source) => new()
{
    Id = source.Id,
    Name = source.Name,
    Source = source.Source,
    DetectorVersion = source.DetectorVersion,
    MarkerRva = source.MarkerRva,
    StartRva = source.StartRva,
    EndRva = source.EndRva,
    Mode = MarkerProtectionMode.Ultra,
    VmComplexity = 7,
    MutationStrength = 2,
    LockToActivation = true
};

var root = args.Length > 0 ? Path.GetFullPath(args[0]) : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
var outDir = Path.Combine(root, "tests", "_reg", "planner-smoke");
Directory.CreateDirectory(outDir);

var vmPath = Path.Combine(root, "tests", "vm_target.exe");
var vm = PeInspector.Inspect(vmPath);
Require(vm is { IsValid: true, TargetArchitecture: ProtectionTargetArchitecture.X64, IsManaged: false, IsDll: false }, "vm_target x64/native detection failed");
Require(vm.Markers.Count == 1, $"expected one NovaProtect marker region, got {vm.Markers.Count}");

var foreignMarkerPath = Path.Combine(root, "tests", "test_target.exe");
if (File.Exists(foreignMarkerPath))
{
    var foreignMarkerTarget = PeInspector.Inspect(foreignMarkerPath);
    Require(foreignMarkerTarget.IsValid && foreignMarkerTarget.Markers.Count == 0, "VMProtect SDK imports must not be exposed as NovaProtect marker objects");
}
else
{
    // Same as above: the foreign-marker fixture is a stripped build artifact.
    Console.WriteLine("[SKIP] foreign marker detection: fixture missing (tests/test_target.exe)");
}

var rule = CopyRule(vm.Markers[0]);
var options = new ProtectionOptions
{
    InputPath = vmPath,
    OutputPath = Path.Combine(outDir, "vm_target_np.exe"),
    Mode = ProtectionMode.Ultra,
    MutationStrength = 2,
    VmComplexity = 7,
    ImportProtection = true,
    PackSections = true,
    EncryptSections = true,
    StripRelocations = true,
    ActivationBinding = "auto",
    ObjectRules = [rule]
};
var plan = ProtectionPlanner.Create(options, vm);
Require(!plan.HasBlockingConflicts, string.Join("; ", plan.Conflicts));
Require(plan.Requested.Any(item => item.Contains("激活/硬件绑定")), "activation request missing");
Require(plan.Effective.Any(item => item.Contains("1 个 marker 区域 VM")), "effective marker count missing");
Require(plan.Effective.Any(item => item.Contains("重定位裁剪")), "relocation trim effective value missing");

var projectPath = Path.Combine(outDir, "planner-smoke.novaprotect.json");
await ProjectStore.SaveProjectAsync(projectPath, options);
var loaded = await ProjectStore.LoadProjectAsync(projectPath);
Require(loaded.SchemaVersion == ProductInfo.ProjectSchemaVersion, "project schema version was not persisted");
Require(loaded.Options.ObjectRules.Count == 1, "project object rules did not round-trip");
Require(loaded.Options.ActivationBinding == "auto", "project activation binding did not round-trip");

var planPath = await ProjectStore.SaveBuildPlanAsync(plan, "prebuild");
Require(File.Exists(planPath), "build plan was not written beside output");
Require(planPath.EndsWith(".novaprotect-prebuild.json", StringComparison.OrdinalIgnoreCase), "prebuild snapshot path is not immutable/separate");
using (var json = JsonDocument.Parse(await File.ReadAllTextAsync(planPath)))
{
    var rootElement = json.RootElement;
    foreach (var property in new[] { "Requested", "Effective", "Skipped", "Conflicts" })
        Require(rootElement.TryGetProperty(property, out _), $"build plan missing {property}");
    Require(rootElement.GetProperty("Stage").GetString() == "prebuild", "build plan stage was not persisted");
    Require(rootElement.TryGetProperty("PlanId", out var planId) && !string.IsNullOrWhiteSpace(planId.GetString()), "build plan id missing");
    Require(rootElement.GetProperty("SchemaVersion").GetInt32() == ProductInfo.BuildPlanSchemaVersion, "build plan schema version mismatch");
}

var forgedRule = CopyRule(vm.Markers[0]);
forgedRule.Source = "manual function scanner";
var forgedPlan = ProtectionPlanner.Create(new ProtectionOptions
{
    InputPath = vmPath,
    OutputPath = Path.Combine(outDir, "forged.exe"),
    Mode = ProtectionMode.Virtualization,
    VmComplexity = 5,
    ObjectRules = [forgedRule]
}, vm);
Require(forgedPlan.Conflicts.Any(item => item.Contains("不是受信任的 NovaProtect SDK marker 来源")), "forged object provenance must be blocked");

var x86Path = Path.Combine(root, "tests", "hostname32.exe");
if (File.Exists(x86Path))
{
    var x86 = PeInspector.Inspect(x86Path);
    Require(x86 is { IsValid: true, TargetArchitecture: ProtectionTargetArchitecture.X86, IsManaged: false }, "x86 detection failed");
    Require(ProtectionPlanner.MatrixFor(x86).Any(cell => cell.Name.Contains("marker VM") && cell.State == CapabilityState.Unsupported), "x86 matrix must reject marker VM");
}
else
{
    // The x86 fixture is a build artifact that is stripped from the source
    // package; without it the x86 matrix cannot be exercised here.
    Console.WriteLine("[SKIP] x86 detection: fixture missing (tests/hostname32.exe)");
}
var uiExe = Path.Combine(root, "ui", "bin", "x64", "Release", "net10.0-windows10.0.19041.0", "win-x64", "NovaProtect.exe");
if (File.Exists(uiExe))
{
    var managed = PeInspector.Inspect(uiExe);
    Require(managed.IsValid && managed.IsManaged && !managed.IsDll, ".NET EXE detection failed");
    var managedPlan = ProtectionPlanner.Create(new ProtectionOptions { InputPath = uiExe, OutputPath = Path.Combine(outDir, "managed.exe") }, managed);
    Require(!managedPlan.HasBlockingConflicts, string.Join("; ", managedPlan.Conflicts));
    Require(managedPlan.Effective.Any(item => item.Contains("CLR 安全封装")), ".NET EXE plan must select CLR envelope mode");
}

var arm64Path = Path.Combine(outDir, "arm64-probe.exe");
var arm64Bytes = await File.ReadAllBytesAsync(vmPath);
var peOffset = BinaryPrimitives.ReadInt32LittleEndian(arm64Bytes.AsSpan(0x3C, 4));
BinaryPrimitives.WriteUInt16LittleEndian(arm64Bytes.AsSpan(peOffset + 4, 2), 0xAA64);
await File.WriteAllBytesAsync(arm64Path, arm64Bytes);
var arm64 = PeInspector.Inspect(arm64Path);
Require(arm64.TargetArchitecture == ProtectionTargetArchitecture.Arm64, "ARM64 detection failed");
Require(ProtectionPlanner.Create(new ProtectionOptions { InputPath = arm64Path, OutputPath = Path.Combine(outDir, "arm64_np.exe") }, arm64).Conflicts.Any(item => item.Contains("ARM64 loader")), "ARM64 plan must reject the missing loader");

var sampleRoot = Path.Combine(root, "tests", "samples");
var sampleExpectations = new (string RelativePath, ExecutableToolchain Toolchain)[]
{
    (Path.Combine("cpp", "cpp-sample.exe"), ExecutableToolchain.Cpp),
    (Path.Combine("csharp", "csharp-sample.exe"), ExecutableToolchain.DotNet),
    (Path.Combine("vb", "vb-sample.exe"), ExecutableToolchain.DotNet),
    (Path.Combine("rust", "rust-sample.exe"), ExecutableToolchain.Rust),
    (Path.Combine("go", "go-sample.exe"), ExecutableToolchain.Go)
};
foreach (var (relativePath, expectedToolchain) in sampleExpectations)
{
    var samplePath = Path.Combine(sampleRoot, relativePath);
    Require(File.Exists(samplePath), $"missing toolchain sample: {relativePath}");
    var sample = PeInspector.Inspect(samplePath);
    Require(sample.IsValid && !sample.IsDll && sample.Toolchain == expectedToolchain,
        $"toolchain detection failed for {relativePath}: {sample.Toolchain}");
}

var dllPath = Path.Combine(root, "tests", "_reg", "export_target.dll");
if (File.Exists(dllPath))
{
    var dll = PeInspector.Inspect(dllPath);
    Require(dll.IsValid && dll.IsDll, "native DLL detection failed");
    var dllPlan = ProtectionPlanner.Create(new ProtectionOptions
    {
        InputPath = dllPath,
        OutputPath = Path.Combine(outDir, "export_target_np.dll"),
        StripRelocations = true,
        StripExports = true
    }, dll);
    Require(dllPlan.Conflicts.Count(item => item.Contains("DLL")) >= 2, "DLL trim conflicts missing");
    Require(!dllPlan.Effective.Any(item => item.Contains("裁剪") && !item.Contains("调试")), "blocked DLL trims must not be reported as effective");
}

// Rule-level conflicts that hit the same check are reported as one line
// instead of one line per rule: asking for an activation lock on twenty
// functions must not bury the actual problem under twenty identical lines.
if (File.Exists(vmPath))
{
    var vmTarget = PeInspector.Inspect(vmPath);
    var manyRules = Enumerable.Range(0, 20).Select(index => new ProtectionObjectRule
    {
        Id = $"func-{index:X8}",
        Name = $"func_{index:X8}",
        Source = ProductInfo.FunctionSource,
        DetectorVersion = ProductInfo.FunctionDetectorVersion,
        StartRva = 0x1000 + (uint)index * 0x200,
        EndRva = 0x1000 + (uint)index * 0x200 + 0x100,
        Mode = MarkerProtectionMode.Virtualization,
        VmComplexity = 6,
        LockToActivation = true
    }).ToList();

    var aggregated = ProtectionPlanner.Create(new ProtectionOptions
    {
        InputPath = vmPath,
        OutputPath = Path.Combine(outDir, "vm_target_np.exe"),
        Mode = ProtectionMode.Virtualization,
        VmComplexity = 6,
        ObjectRules = manyRules
    }, vmTarget);

    var activationLines = aggregated.Conflicts.Count(item => item.Contains("激活锁定"));
    Require(activationLines == 1, $"the activation conflict must be one line, got {activationLines}");
    Require(aggregated.Conflicts.Any(item => item.Contains("20 项") && item.Contains("激活锁定")),
        "the aggregated conflict must state how many rules are affected");
    Require(aggregated.Conflicts.Count < 5, $"the conflict list must stay short, got {aggregated.Conflicts.Count}");
}

Console.WriteLine("PLANNER-SMOKE-OK");
