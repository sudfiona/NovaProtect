using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public sealed partial class ProtectorService
{
    public async Task<ProtectionRunResult> RunAsync(
        ProtectionOptions options,
        Action<int, string> onProgress,
        CancellationToken cancellationToken)
    {
        var cli = Path.Combine(AppContext.BaseDirectory, "NovaProtect.Engine.exe");
        if (!File.Exists(cli))
            return new ProtectionRunResult(false, -1, $"找不到保护核心：{cli}");

        var start = new ProcessStartInfo
        {
            FileName = cli,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        Add(start, options.InputPath);
        Add(start, "-o", options.OutputPath);
        Add(start, "-mode", options.Mode switch
        {
            ProtectionMode.Mutation => "mutation",
            ProtectionMode.Virtualization => "virtualization",
            _ => "ultra"
        });
        Add(start, "-mut", options.MutationStrength.ToString());
        Add(start, "-vm", options.VmComplexity.ToString());
        // Only emitted when the user turned it off. The core defaults to on, so
        // passing the flag is the exception; passing "-norevirtualization"
        // explicitly keeps the intent visible in the argument log instead of
        // relying on a default that could change.
        Flag(start, !options.EnableRevirtualization || options.RevirtualizationLevel <= 0, "-norevirtualization");
        if (options.EnableRevirtualization && options.RevirtualizationLevel > 0)
            Add(start, "-revirt-level", options.RevirtualizationLevel.ToString());
        Add(start, "-ad", options.AntiDebugLevel.ToString());
        Add(start, "-avm", options.AntiVmLevel.ToString());

        Flag(start, options.MemoryProtection, "-memory");
        Flag(start, options.ImportProtection, "-imports");
        Flag(start, options.ResourceProtection, "-resources");
        Flag(start, options.SandboxGuard, "-sandbox-guard");
        Flag(start, options.AntiDump, "-anti-dump");
        Flag(start, options.EnvCheck, "-env-check");
        Flag(start, options.SelfIsolation, "-self-isolate");
        Flag(start, options.AuditRecheck, "-audit-recheck");
        Flag(start, !options.PackSections, "-nopack");
        Flag(start, !options.EncryptSections, "-noencrypt");
        Flag(start, !options.StripDebugInfo, "-keepdebug");
        Flag(start, options.StripRelocations, "-stripreloc");
        Flag(start, options.StripExports, "-stripexport");
        AddOptional(start, "-watermark", options.Watermark);
        AddOptional(start, "-license", options.LicenseKey);
        AddOptional(start, "-activation", options.ActivationBinding);

        AppendEvasion(start, options.Evasion);
        AppendEnvironmentGate(start, options.Environment);

        // Windows caps the command line at 32767 characters. Passing one
        // argument per selected function blows that limit as soon as a few
        // hundred functions are checked, and the engine then never starts.
        // Rules therefore go through a file, which has no such ceiling.
        var functionRules = new List<string>();
        var markerRules = new List<string>();
        foreach (var rule in options.ObjectRules)
        {
            if (string.Equals(rule.Source, ProductInfo.FunctionSource, StringComparison.Ordinal) &&
                string.Equals(rule.DetectorVersion, ProductInfo.FunctionDetectorVersion, StringComparison.Ordinal))
            {
                // Scanned function: the RVA range is the whole function body,
                // so the packer lowers it directly (no marker wrapping).
                functionRules.Add($"{rule.StartRva:X}-{rule.EndRva:X}-{ModeName(rule.Mode)}-{rule.VmComplexity}-{rule.MutationStrength}-{(rule.LockToActivation ? 1 : 0)}");
                continue;
            }
            if (!string.Equals(rule.Source, ProductInfo.MarkerSource, StringComparison.Ordinal) ||
                !string.Equals(rule.DetectorVersion, ProductInfo.MarkerDetectorVersion, StringComparison.Ordinal))
                throw new InvalidOperationException($"对象规则 {rule.Name} 不是由 NovaProtect SDK marker 检测器生成");
            markerRules.Add($"{rule.StartRva:X}-{rule.EndRva:X}-{ModeName(rule.Mode)}-{rule.VmComplexity}-{rule.MutationStrength}-{(rule.LockToActivation ? 1 : 0)}");
        }

        string? functionRuleFile = null;
        string? markerRuleFile = null;
        try
        {
            if (functionRules.Count > 0)
            {
                functionRuleFile = WriteRuleFile(functionRules);
                Add(start, "-funcfile", functionRuleFile);
            }
            if (markerRules.Count > 0)
            {
                markerRuleFile = WriteRuleFile(markerRules);
                Add(start, "-regionfile", markerRuleFile);
            }
        }
        catch
        {
            DeleteRuleFile(functionRuleFile);
            DeleteRuleFile(markerRuleFile);
            throw;
        }

        foreach (var virtualFile in options.VirtualFiles) Add(start, "-vf", virtualFile);

        using var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        var recent = new Queue<string>();
        var started = false;
        void Handle(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            lock (recent)
            {
                recent.Enqueue(line);
                while (recent.Count > 8) recent.Dequeue();
            }

            var match = ProgressRegex().Match(line);
            var percent = match.Success && int.TryParse(match.Groups[1].Value, out var value) ? value : -1;
            onProgress(percent, line);
        }

        process.OutputDataReceived += (_, e) => Handle(e.Data);
        process.ErrorDataReceived += (_, e) => Handle(e.Data);

        try
        {
            using var invocation = ClientInvocation.Create(start);
            if (!process.Start()) return new ProtectionRunResult(false, -1, "无法启动保护核心");
            started = true;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await using var registration = cancellationToken.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
            });
            await invocation.AuthorizeAsync(process, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            string summary;
            lock (recent) summary = string.Join(Environment.NewLine, recent);
            return new ProtectionRunResult(process.ExitCode == 0, process.ExitCode, summary, Describe(start));
        }
        catch (OperationCanceledException)
        {
            return new ProtectionRunResult(false, -2, "操作已取消");
        }
        catch (Exception ex)
        {
            if (started)
            {
                try
                {
                    using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await process.WaitForExitAsync(wait.Token);
                }
                catch { }
            }

            string details;
            lock (recent) details = string.Join(Environment.NewLine, recent);
            ClientDiagnosticLog.Error("Protection core invocation failed", ex);
            var summary = string.IsNullOrWhiteSpace(details)
                ? ex.Message
                : $"{ex.Message}{Environment.NewLine}{details}";
            var exitCode = started && process.HasExited ? process.ExitCode : -1;
            return new ProtectionRunResult(false, exitCode, summary);
        }
        finally
        {
            DeleteRuleFile(functionRuleFile);
            DeleteRuleFile(markerRuleFile);
        }
    }

    // Write region rules to a temporary file. The content is pure ASCII
    // (hexadecimal RVAs and fixed keywords), so the encoding never matters.
    private static string WriteRuleFile(IReadOnlyList<string> rules)
    {
        var path = Path.Combine(Path.GetTempPath(), $"novaprotect-rules-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(path, rules, new UTF8Encoding(false));
        return path;
    }

    private static void DeleteRuleFile(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try { File.Delete(path); } catch { }
    }

    public async Task<(bool Success, string Output)> InspectAsync(string path, params string[] command)
    {
        var cli = Path.Combine(AppContext.BaseDirectory, "NovaProtect.Engine.exe");
        var start = new ProcessStartInfo
        {
            FileName = cli,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        if (!string.IsNullOrWhiteSpace(path)) Add(start, path);
        foreach (var item in command) start.ArgumentList.Add(item);
        try
        {
            using var invocation = ClientInvocation.Create(start);
            using var process = Process.Start(start);
            if (process is null) return (false, "无法启动检查工具");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            try { await invocation.AuthorizeAsync(process, CancellationToken.None); }
            catch (Exception ex) { return (false, ex.Message + "\n" + await stdout + await stderr); }
            await process.WaitForExitAsync();
            var output = await stdout + await stderr;
            return (process.ExitCode == 0, output.Trim());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>
    /// Render the argv the core received. Quoted so a path with a space stays
    /// readable and the line can be copy-pasted back into a shell.
    /// </summary>
    private static string Describe(ProcessStartInfo start) =>
        start.FileName + " " + string.Join(" ", start.ArgumentList.Select(value =>
            value.Length > 0 && value.IndexOfAny([' ', '\t', '"']) < 0 ? value : '"' + value.Replace("\"", "\\\"") + '"'));

    private static void Add(ProcessStartInfo start, params string[] values)
    {
        foreach (var value in values) start.ArgumentList.Add(value);
    }

    /// <summary>
    /// Emit the <c>-evasion</c> family. <c>-evasion</c> rewrites the engine's
    /// whole <c>EvasionConfig</c> to that profile's defaults, so it has to come
    /// first and every per-field override after it, or the profile defaults would
    /// silently win.
    /// </summary>
    private static void AppendEvasion(ProcessStartInfo start, EvasionOptions evasion)
    {
        Add(start, "-evasion", evasion.Profile switch
        {
            EvasionProfile.Off => "off",
            EvasionProfile.Balanced => "balanced",
            EvasionProfile.Aggressive => "aggressive",
            _ => "paranoid"
        });

        // An explicit seed reproduces a build byte for byte; an empty box plus
        // -evasion-reseed draws fresh entropy. Never emit -evasion-seed with an
        // empty or zero value: the engine treats that as exit code 2.
        if (!string.IsNullOrWhiteSpace(evasion.SeedHex) && evasion.HasValidSeed)
            Add(start, "-evasion-seed", evasion.SeedHex.Trim());
        Flag(start, evasion.Reseed && string.IsNullOrWhiteSpace(evasion.SeedHex), "-evasion-reseed");

        Add(start, "-junk", Math.Clamp(evasion.JunkDensity, 0, 8).ToString());
        Add(start, "-anti-sandbox", Math.Clamp(evasion.AntiSandboxLevel, 0, 3).ToString());
        Add(start, "-detonate-delay", Math.Clamp(evasion.DetonateDelayMs, 0, 600000).ToString());
        Add(start, "-memstream", Math.Clamp(evasion.MemStreamRounds, 0, 3).ToString());
        Add(start, "-unhook", evasion.Unhook ? "1" : "0");
        Add(start, "-kernel-level", Math.Clamp(evasion.KernelLevel, 0, 3).ToString());
        Add(start, "-hv-exit-cost", evasion.HypervisorExitCost ? "1" : "0");
    }

    /// <summary>
    /// Emit the environment-gate thresholds. The engine treats 0 as "no
    /// minimum", so zero values are skipped rather than passed through.
    /// </summary>
    private static void AppendEnvironmentGate(ProcessStartInfo start, EnvironmentGateOptions gate)
    {
        Add(start, "-sandbox-threshold", gate.SandboxThreshold.ToString());
        Add(start, "-env-threshold", gate.EnvThreshold.ToString());
        if (gate.MinCpuCount > 0) Add(start, "-min-cpu", gate.MinCpuCount.ToString());
        if (gate.MinRamMb > 0) Add(start, "-min-ram-mb", gate.MinRamMb.ToString());
        if (gate.MinUptimeMs > 0) Add(start, "-min-uptime-ms", gate.MinUptimeMs.ToString());
        if (gate.MinScreenWidth > 0) Add(start, "-min-screen-w", gate.MinScreenWidth.ToString());
        if (gate.MinScreenHeight > 0) Add(start, "-min-screen-h", gate.MinScreenHeight.ToString());
        if (gate.MinMonitorCount > 0) Add(start, "-min-monitor", gate.MinMonitorCount.ToString());
    }

    private static void AddOptional(ProcessStartInfo start, string name, string value)
    {
        if (!string.IsNullOrWhiteSpace(value)) Add(start, name, value);
    }

    private static void Flag(ProcessStartInfo start, bool enabled, string value)
    {
        if (enabled) start.ArgumentList.Add(value);
    }

    private static string ModeName(MarkerProtectionMode mode) => mode switch
    {
        MarkerProtectionMode.Skip => "skip",
        MarkerProtectionMode.Virtualization => "virtualization",
        MarkerProtectionMode.Mutation => "mutation",
        MarkerProtectionMode.Ultra => "ultra",
        _ => "inherit"
    };

    [GeneratedRegex(@"^\[\s*(\d{1,3})%\]")]
    private static partial Regex ProgressRegex();
}

