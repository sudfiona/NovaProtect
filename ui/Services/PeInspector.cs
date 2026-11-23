using System.Buffers.Binary;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public static class PeInspector
{
    public static PeSummary Inspect(string path)
    {
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length < 0x100) return Invalid(stream.Length, Localizer.T("文件太小，不是有效的 PE 映像"));

            Span<byte> dos = stackalloc byte[64];
            stream.ReadExactly(dos);
            if (dos[0] != (byte)'M' || dos[1] != (byte)'Z') return Invalid(stream.Length, Localizer.T("缺少 MZ 文件头"));

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3c..0x40]);
            if (peOffset < 0 || peOffset + 256 > stream.Length) return Invalid(stream.Length, Localizer.T("PE 头偏移无效"));

            stream.Position = peOffset;
            Span<byte> header = stackalloc byte[256];
            stream.ReadExactly(header);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header[..4]) != 0x4550)
                return Invalid(stream.Length, Localizer.T("缺少 PE 签名"));

            var machine = BinaryPrimitives.ReadUInt16LittleEndian(header[4..6]);
            var targetArchitecture = machine switch
            {
                0x014c => ProtectionTargetArchitecture.X86,
                0x8664 => ProtectionTargetArchitecture.X64,
                0xaa64 => ProtectionTargetArchitecture.Arm64,
                _ => ProtectionTargetArchitecture.Unknown
            };
            var architecture = machine switch
            {
                0x014c => "x86 (32-bit)",
                0x8664 => "x64 (64-bit)",
                0xaa64 => "ARM64",
                0x01c4 => "ARM (32-bit)",
                _ => Localizer.F("未知架构 0x{0:X4}", machine)
            };

            var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(header[22..24]);
            var isDll = (characteristics & 0x2000) != 0;
            var optionalMagic = BinaryPrimitives.ReadUInt16LittleEndian(header[24..26]);
            var dataDirectoryOffset = optionalMagic == 0x20b ? 24 + 112 : 24 + 96;
            var comOffset = dataDirectoryOffset + 14 * 8;
            var isDotNet = comOffset + 8 <= header.Length &&
                           BinaryPrimitives.ReadUInt32LittleEndian(header[comOffset..(comOffset + 4)]) != 0 &&
                           BinaryPrimitives.ReadUInt32LittleEndian(header[(comOffset + 4)..(comOffset + 8)]) != 0;
            if (!isDotNet) isDotNet = IsManagedAppHost(path, stream);

            var kind = isDotNet
                ? Localizer.T(isDll ? ".NET DLL（C#/VB）" : ".NET EXE（C#/VB）")
                : Localizer.T(isDll ? "原生 DLL" : "原生 EXE");
            var toolchain = DetectToolchain(path, stream, isDotNet, isDll);
            var toolchainDisplay = toolchain switch
            {
                ExecutableToolchain.DotNet => "C# / VB .NET",
                ExecutableToolchain.Rust => "Rust",
                ExecutableToolchain.Go => "Golang",
                ExecutableToolchain.Cpp => "C / C++",
                _ => Localizer.T("未知 PE 工具链")
            };
            var detail = targetArchitecture switch
            {
                ProtectionTargetArchitecture.X64 when !isDotNet => Localizer.T("支持 x64 loader、导入虚拟化、SDK marker 区域 VM 与函数扫描 VM；函数面板可枚举并勾选任意函数。"),
                ProtectionTargetArchitecture.X86 when !isDotNet => Localizer.T("支持 x86 loader、区段加密和导入虚拟化；VM/许可运行时仅支持 x64。"),
                ProtectionTargetArchitecture.Arm64 => Localizer.T("已识别 ARM64，但当前核心没有 ARM64 loader，构建会被拒绝。"),
                _ when isDotNet => Localizer.T("已识别 C#/VB .NET EXE；采用 CLR 安全封装保护，不重写托管元数据和 IL。"),
                _ => Localizer.T("当前核心不支持此架构。")
            };
            var markers = targetArchitecture is ProtectionTargetArchitecture.X64 or ProtectionTargetArchitecture.X86
                ? FindMarkers(path, stream, peOffset, header, targetArchitecture)
                : [];
            return new PeSummary(true, targetArchitecture, architecture, kind, isDotNet, isDll, toolchain, toolchainDisplay, stream.Length, detail, markers);
        }
        catch (Exception ex)
        {
            return new PeSummary(false, ProtectionTargetArchitecture.Unknown, Localizer.T("未知"),
                Localizer.T("读取失败"), false, false,
                ExecutableToolchain.Unknown, Localizer.T("未知 PE 工具链"), 0, ex.Message, []);
        }
    }

    private sealed record Section(uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics);

    private static List<ProtectionObjectRule> FindMarkers(
        string path,
        FileStream stream,
        int peOffset,
        ReadOnlySpan<byte> header,
        ProtectionTargetArchitecture architecture)
    {
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(header[6..8]);
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(header[20..22]);
        var sectionTable = peOffset + 24 + optionalSize;
        if (sectionCount == 0 || sectionCount > 96 || sectionTable < 0 || sectionTable + sectionCount * 40L > stream.Length)
            return [];

        stream.Position = sectionTable;
        var rawSections = new byte[sectionCount * 40];
        stream.ReadExactly(rawSections);
        var sections = new List<Section>(sectionCount);
        for (var i = 0; i < sectionCount; i++)
        {
            var row = rawSections.AsSpan(i * 40, 40);
            sections.Add(new Section(
                BinaryPrimitives.ReadUInt32LittleEndian(row[12..16]),
                BinaryPrimitives.ReadUInt32LittleEndian(row[8..12]),
                BinaryPrimitives.ReadUInt32LittleEndian(row[20..24]),
                BinaryPrimitives.ReadUInt32LittleEndian(row[16..20]),
                BinaryPrimitives.ReadUInt32LittleEndian(row[36..40])));
        }

        var beginPrefix = architecture == ProtectionTargetArchitecture.X64
            ? new byte[] { 0x48, 0x8D, 0x0D, 0, 0, 0, 0 }
            : new byte[] { 0x8D, 0x0D, 0, 0, 0, 0 };
        var beginLength = beginPrefix.Length + 20;
        var regions = new List<ProtectionObjectRule>();
        var ordinal = 1;

        foreach (var section in sections.Where(s => (s.Characteristics & 0x20000000) != 0 && s.RawSize > 0))
        {
            if (section.RawOffset + section.RawSize > stream.Length || section.RawSize > 128 * 1024 * 1024) continue;
            stream.Position = section.RawOffset;
            var bytes = new byte[section.RawSize];
            stream.ReadExactly(bytes);

            var cursor = 0;
            while (cursor + beginLength <= bytes.Length)
            {
                var begin = IndexOfBegin(bytes, cursor, beginPrefix);
                if (begin < 0) break;
                var bodyStart = begin + beginLength;
                var end = IndexOfNops(bytes, bodyStart, 20);
                if (end < 0) break;
                if (end > bodyStart)
                {
                    var markerRva = checked(section.VirtualAddress + (uint)begin);
                    var startRva = checked(section.VirtualAddress + (uint)bodyStart);
                    var endRva = checked(section.VirtualAddress + (uint)end);
                    regions.Add(new ProtectionObjectRule
                    {
                        Id = $"marker-{markerRva:X8}",
                        Name = Localizer.F("SDK 区域 {0}", ordinal++),
                        Source = ProductInfo.MarkerSource,
                        DetectorVersion = ProductInfo.MarkerDetectorVersion,
                        MarkerRva = markerRva,
                        StartRva = startRva,
                        EndRva = endRva
                    });
                }
                cursor = end + 20;
            }
        }
        return regions;
    }

    private static int IndexOfBegin(byte[] bytes, int start, byte[] prefix)
    {
        for (var i = Math.Max(start, 0); i + prefix.Length + 20 <= bytes.Length; i++)
        {
            if (!bytes.AsSpan(i, prefix.Length).SequenceEqual(prefix)) continue;
            if (IsNops(bytes, i + prefix.Length, 20)) return i;
        }
        return -1;
    }

    private static int IndexOfNops(byte[] bytes, int start, int count)
    {
        for (var i = Math.Max(start, 0); i + count <= bytes.Length; i++)
            if (IsNops(bytes, i, count)) return i;
        return -1;
    }

    private static bool IsNops(byte[] bytes, int start, int count)
    {
        for (var i = 0; i < count; i++)
            if (bytes[start + i] != 0x90) return false;
        return true;
    }

    private static ExecutableToolchain DetectToolchain(string path, FileStream stream, bool isDotNet, bool isDll)
    {
        if (isDotNet) return ExecutableToolchain.DotNet;
        if (isDll) return ExecutableToolchain.Unknown;

        var originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            var sampleSize = (int)Math.Min(stream.Length, 16 * 1024 * 1024);
            var bytes = new byte[sampleSize];
            stream.ReadExactly(bytes);
            var text = System.Text.Encoding.Latin1.GetString(bytes);
            var lowerText = text.ToLowerInvariant();
            if (text.Contains("Go build ID:", StringComparison.Ordinal) ||
                text.Contains("runtime.main", StringComparison.Ordinal) ||
                text.Contains("runtime.morestack", StringComparison.Ordinal))
                return ExecutableToolchain.Go;
            if (text.Contains("rust_eh_personality", StringComparison.Ordinal) ||
                text.Contains("core::panicking", StringComparison.Ordinal) ||
                text.Contains("rustc_demangle", StringComparison.Ordinal) ||
                lowerText.Contains("/rustc/", StringComparison.Ordinal) ||
                lowerText.Contains("\\rustc\\", StringComparison.Ordinal))
                return ExecutableToolchain.Rust;
            return ExecutableToolchain.Cpp;
        }
        finally { stream.Position = originalPosition; }
    }

    private static bool IsManagedAppHost(string path, FileStream stream)
    {
        if (!string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase)) return false;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var baseName = Path.GetFileNameWithoutExtension(path);
        var managedDllName = baseName + ".dll";
        var managedDll = Path.Combine(directory, managedDllName);
        var runtimeConfig = Path.Combine(directory, baseName + ".runtimeconfig.json");

        var originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            var sampleSize = (int)Math.Min(stream.Length, 8 * 1024 * 1024);
            var bytes = new byte[sampleSize];
            stream.ReadExactly(bytes);
            var needle = System.Text.Encoding.UTF8.GetBytes(managedDllName);
            var hasManagedName = bytes.AsSpan().IndexOf(needle) >= 0;

            // Framework-dependent apphosts normally have sidecar files. A
            // self-contained publish, however, can carry only the managed
            // assembly name in the native host. The hostfxr export table and
            // apphost build path provide the second signal needed here.
            if (File.Exists(managedDll) && File.Exists(runtimeConfig) && hasManagedName) return true;
            var text = System.Text.Encoding.Latin1.GetString(bytes);
            return text.Contains("hostfxr_main", StringComparison.Ordinal) &&
                   text.Contains("apphost.pdb", StringComparison.OrdinalIgnoreCase);
        }
        finally { stream.Position = originalPosition; }
    }

    private static PeSummary Invalid(long size, string detail) =>
        new(false, ProtectionTargetArchitecture.Unknown, Localizer.T("未知"), Localizer.T("无效文件"), false, false,
            ExecutableToolchain.Unknown, Localizer.T("未知 PE 工具链"), size, detail, []);
}

