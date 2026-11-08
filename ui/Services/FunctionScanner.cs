using System.Buffers.Binary;
using System.Text;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

// One function discovered in the target image. RVA ranges are exclusive at
// the end ([Rva, Rva + Size)) and always fall inside an executable section.
public sealed record ScannedFunction(
    uint Rva,
    uint Size,
    string Section,
    string Name,
    bool IsExported,
    bool HasStackFrame,
    string PrologueHex)
{
    // The packer's trampoline needs 51 + 10*regs bytes inside the region,
    // and every region also preserves the interpreter's argument/scratch
    // registers (rax/rcx/rdx/r8-r11), so at least 7 slots are always
    // saved: 51 + 10*7 + 16 slack = 137 bytes minimum. Functions shorter
    // than this are reported as VM-infeasible up front; the packer still
    // makes the final call per region.
    public const uint MinVirtualizableSize = 137;

    public uint EndRva => Rva + Size;

    public string AddressRange => $"0x{Rva:X8} – 0x{EndRva:X8}";

    public string Summary => $"{Name} · {AddressRange} · {Size} 字节";

    public string Feasibility => VmFeasible ? "可虚拟化" : HasStackFrame ? "含栈帧，VM 大概率跳过" : "函数过小，VM 跳过";

    public bool VmFeasible => Size >= MinVirtualizableSize && !HasStackFrame;
}

public sealed class FunctionScanResult
{
    public bool Success { get; init; }
    public string Error { get; init; } = string.Empty;
    public ProtectionTargetArchitecture Architecture { get; init; }
    public IReadOnlyList<ScannedFunction> Functions { get; init; } = [];
    public int TotalRoutines { get; init; }
    public int Skipped { get; init; }
    public string Source { get; init; } = string.Empty;

    public string Summary => Success
        ? $"扫描到 {Functions.Count} 个函数（{Source}，共 {TotalRoutines} 个routine，跳过 {Skipped} 个）"
        : Error;
}

// Enumerates functions in a native PE image the way the VMProtect functions
// panel does. x64 reads the exception directory (.pdata RUNTIME_FUNCTION
// table) which covers every function including static ones. x86 has no
// unwind metadata, so the export directory plus a prologue sweep over the
// executable sections is used as a best-effort fallback.
public static class FunctionScanner
{
    // Hard cap so a pathological image cannot exhaust the UI list. The packer
    // no longer clamps the VM region table to 64 entries, so the selection size
    // is limited only by how many functions the translator can express.
    public const int MaxFunctions = 20000;

    public static FunctionScanResult Scan(string path)
    {
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length < 0x100) return Fail("文件太小，不是有效的 PE 映像");

            Span<byte> dos = stackalloc byte[64];
            stream.ReadExactly(dos);
            if (dos[0] != (byte)'M' || dos[1] != (byte)'Z') return Fail("缺少 MZ 文件头");

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3c..0x40]);
            if (peOffset < 0 || peOffset + 256 > stream.Length) return Fail("PE 头偏移无效");

            stream.Position = peOffset;
            Span<byte> header = stackalloc byte[256];
            stream.ReadExactly(header);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header[..4]) != 0x4550)
                return Fail("缺少 PE 签名");

            var machine = BinaryPrimitives.ReadUInt16LittleEndian(header[4..6]);
            var architecture = machine switch
            {
                0x014c => ProtectionTargetArchitecture.X86,
                0x8664 => ProtectionTargetArchitecture.X64,
                0xaa64 => ProtectionTargetArchitecture.Arm64,
                _ => ProtectionTargetArchitecture.Unknown
            };
            if (architecture == ProtectionTargetArchitecture.Unknown)
                return Fail($"不支持的机器类型 0x{machine:X4}（仅支持 x86 / x64）");
            if (architecture == ProtectionTargetArchitecture.Arm64)
                return Fail("ARM64 映像没有可枚举的 unwind 元数据，当前核心也不支持 ARM64 保护");

            var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(header[20..22]);
            var dataDirectoryOffset = peOffset + 24 + (machine == 0x8664 ? 112 : 96);
            stream.Position = dataDirectoryOffset;
            Span<byte> directories = stackalloc byte[16 * 8];
            stream.ReadExactly(directories);
            var exportDirRva = BinaryPrimitives.ReadUInt32LittleEndian(directories[0..4]);
            var exceptionDirRva = BinaryPrimitives.ReadUInt32LittleEndian(directories[(3 * 8)..(3 * 8 + 4)]);
            var exceptionDirSize = BinaryPrimitives.ReadUInt32LittleEndian(directories[(3 * 8 + 4)..(3 * 8 + 8)]);

            var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(header[6..8]);
            var sectionTable = peOffset + 24 + optionalSize;
            if (sectionCount == 0 || sectionCount > 96 || sectionTable + sectionCount * 40L > stream.Length)
                return Fail("节表无效");

            stream.Position = sectionTable;
            var rawSections = new byte[sectionCount * 40];
            stream.ReadExactly(rawSections);
            var sections = new List<Section>(sectionCount);
            for (var i = 0; i < sectionCount; i++)
            {
                var row = new ReadOnlySpan<byte>(rawSections, i * 40, 40);
                sections.Add(new Section(
                    BinaryPrimitives.ReadUInt32LittleEndian(row[12..16]),
                    BinaryPrimitives.ReadUInt32LittleEndian(row[8..12]),
                    BinaryPrimitives.ReadUInt32LittleEndian(row[20..24]),
                    BinaryPrimitives.ReadUInt32LittleEndian(row[16..20]),
                    BinaryPrimitives.ReadUInt32LittleEndian(row[36..40]),
                    SectionName(row[..8])));
            }

            var exports = exportDirRva != 0
                ? ReadExports(stream, sections, exportDirRva)
                : new Dictionary<uint, string>();

            if (architecture == ProtectionTargetArchitecture.X64 && exceptionDirRva != 0)
            {
                var (functions, total, skipped) = ScanPdata(stream, sections, exceptionDirRva, exceptionDirSize, exports);
                return new FunctionScanResult
                {
                    Success = true,
                    Architecture = architecture,
                    Functions = functions,
                    TotalRoutines = total,
                    Skipped = skipped,
                    Source = ".pdata 异常目录"
                };
            }

            var (heuristic, totalH, skippedH) = ScanHeuristic(stream, sections, exports);
            return new FunctionScanResult
            {
                Success = true,
                Architecture = architecture,
                Functions = heuristic,
                TotalRoutines = totalH,
                Skipped = skippedH,
                Source = architecture == ProtectionTargetArchitecture.X86
                    ? "导出表 + 代码序言扫描"
                    : "代码序言扫描（无异常目录）"
            };
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // ---------------------------------------------------------------- x64 ----

    // RUNTIME_FUNCTION { DWORD BeginAddress; DWORD EndAddress; DWORD UnwindInfo; }
    private static (List<ScannedFunction>, int, int) ScanPdata(
        FileStream stream, List<Section> sections, uint exceptionDirRva, uint exceptionDirSize,
        Dictionary<uint, string> exports)
    {
        var table = FindSection(sections, exceptionDirRva);
        if (table is null) return ([], 0, 0);

        // The exception directory has its own RVA and size inside data
        // directory #3. Reading it from the section head, or counting with
        // the section's raw size, pulls in unrelated bytes and reports the
        // wrong number of routines.
        var dirOffset = table.Value.RawOffset + (exceptionDirRva - table.Value.VirtualAddress);
        if (dirOffset < 0 || dirOffset >= stream.Length) return ([], 0, 0);
        var totalBytes = exceptionDirSize != 0 ? exceptionDirSize : table.Value.RawSize;
        if (totalBytes > table.Value.RawSize) totalBytes = table.Value.RawSize;
        var entries = (int)(totalBytes / 12);
        if (entries <= 0) return ([], 0, 0);

        var functions = new List<ScannedFunction>(Math.Min(entries, MaxFunctions));
        var skipped = 0;
        stream.Position = dirOffset;
        var buffer = new byte[totalBytes];
        stream.ReadExactly(buffer);

        for (var i = 0; i < entries; i++)
        {
            var begin = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, i * 12, 4));
            var end = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, i * 12 + 4, 4));
            if (end <= begin) { skipped++; continue; }
            var section = FindSection(sections, begin);
            if (section is null || (section.Value.Characteristics & 0x20000000) == 0)
            {
                skipped++;   // chained/unwind metadata pointing outside code
                continue;
            }
            if (functions.Count >= MaxFunctions) { skipped += entries - i; break; }

            functions.Add(new ScannedFunction(
                begin,
                end - begin,
                section.Value.Name,
                exports.TryGetValue(begin, out var name) ? name : $"sub_{begin:X8}",
                exports.ContainsKey(begin),
                DetectStackFrame(stream, section.Value, begin),
                ReadPrologue(stream, section.Value, begin, 16)));
        }

        functions.Sort(static (a, b) => a.Rva.CompareTo(b.Rva));
        return (functions, entries, skipped);
    }

    // ---------------------------------------------------------------- x86 ----

    // Best-effort sweep: classic prologues (push ebp; mov ebp,esp and the
    // 64-bit forms) mark function starts inside executable sections. This is
    // a heuristic and can over- or under-count; the UI labels the source.
    private static (List<ScannedFunction>, int, int) ScanHeuristic(
        FileStream stream, List<Section> sections, Dictionary<uint, string> exports)
    {
        var candidates = new List<ScannedFunction>();
        var seen = new HashSet<uint>();

        // Exported functions are known entry points even when their prologue
        // does not match the classic patterns.
        foreach (var (rva, name) in exports)
        {
            var section = FindSection(sections, rva);
            if (section is null || (section.Value.Characteristics & 0x20000000) == 0) continue;
            if (!seen.Add(rva)) continue;
            candidates.Add(new ScannedFunction(
                rva, 0, section.Value.Name, name, true,
                DetectStackFrame(stream, section.Value, rva),
                ReadPrologue(stream, section.Value, rva, 16)));
        }

        foreach (var section in sections)
        {
            if ((section.Characteristics & 0x20000000) == 0 || section.RawSize == 0) continue;
            if (section.RawOffset + section.RawSize > stream.Length || section.RawSize > 64 * 1024 * 1024) continue;

            stream.Position = section.RawOffset;
            var bytes = new byte[section.RawSize];
            stream.ReadExactly(bytes);

            for (var i = 0; i + 5 <= bytes.Length; i++)
            {
                var isX86 = bytes[i] == 0x55 && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xEC;
                var isX64 = bytes[i] == 0x55 && i + 4 <= bytes.Length &&
                            bytes[i + 1] == 0x48 && bytes[i + 2] == 0x89 && bytes[i + 3] == 0xE5;
                if (!isX86 && !isX64) continue;
                var rva = checked(section.VirtualAddress + (uint)i);
                if (rva == 0 || !seen.Add(rva)) continue;
                candidates.Add(new ScannedFunction(
                    rva, 0, section.Name,
                    exports.TryGetValue(rva, out var n) ? n : $"sub_{rva:X8}",
                    exports.ContainsKey(rva), true, ReadPrologue(stream, section, rva, 16)));
                if (candidates.Count >= MaxFunctions) break;
            }
        }

        // Close each function at the next start so every entry has a size.
        var ordered = candidates.OrderBy(c => c.Rva).ToList();
        var functions = new List<ScannedFunction>(ordered.Count);
        for (var i = 0; i < ordered.Count; i++)
        {
            var current = ordered[i];
            var next = i + 1 < ordered.Count ? ordered[i + 1].Rva : current.Rva + 0x1000;
            var size = next > current.Rva ? Math.Min(next - current.Rva, 0x2000u) : 0;
            functions.Add(current with { Size = size });
        }
        return (functions, ordered.Count, 0);
    }

    // ------------------------------------------------------------- exports ---

    private static Dictionary<uint, string> ReadExports(FileStream stream, List<Section> sections, uint exportDirRva)
    {
        var map = new Dictionary<uint, string>();
        var dir = FindSection(sections, exportDirRva);
        if (dir is null || dir.Value.RawSize < 40) return map;

        // The export directory lives at exportDirRva inside its section, so
        // the table has to be read from that offset - not from the section
        // head, which may hold unrelated data.
        var dirOffset = dir.Value.RawOffset + (exportDirRva - dir.Value.VirtualAddress);
        if (dirOffset < 0 || dirOffset + 40 > stream.Length) return map;

        stream.Position = dirOffset;
        var buffer = new byte[40];
        stream.ReadExactly(buffer);
        var ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 16, 4));
        var numberOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 20, 4));
        var numberOfNames = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 24, 4));
        var addressTableRva = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 28, 4));
        var nameTableRva = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 32, 4));
        var ordinalTableRva = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 36, 4));
        if (numberOfNames == 0 || numberOfNames > 65536) return map;
        if (numberOfFunctions == 0 || numberOfFunctions > 65536) return map;

        var nameSection = FindSection(sections, nameTableRva);
        var ordinalSection = FindSection(sections, ordinalTableRva);
        var addressSection = FindSection(sections, addressTableRva);
        if (nameSection is null || ordinalSection is null || addressSection is null) return map;

        // The name-pointer table and the ordinal table are parallel arrays of
        // NumberOfNames entries; the ordinal table already stores the index
        // into the export address table, so it must be used as-is. Subtracting
        // the ordinal base shifts every name onto the neighbouring function
        // (and drops every name outright once the base exceeds the index,
        // which is how user32.dll lost all 1024 of its exports).
        stream.Position = nameSection.Value.RawOffset + (nameTableRva - nameSection.Value.VirtualAddress);
        var nameRows = new byte[numberOfNames * 4];
        stream.ReadExactly(nameRows);
        stream.Position = ordinalSection.Value.RawOffset + (ordinalTableRva - ordinalSection.Value.VirtualAddress);
        var ordinalRows = new byte[numberOfNames * 2];
        stream.ReadExactly(ordinalRows);
        stream.Position = addressSection.Value.RawOffset + (addressTableRva - addressSection.Value.VirtualAddress);
        var addressRows = new byte[numberOfFunctions * 4];
        stream.ReadExactly(addressRows);

        for (var i = 0; i < numberOfNames; i++)
        {
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(nameRows, i * 4, 4));
            var symbol = ReadCString(stream, sections, nameRva);
            if (string.IsNullOrEmpty(symbol)) continue;
            var eatIndex = BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(ordinalRows, i * 2, 2));
            if (eatIndex >= numberOfFunctions) continue;
            var functionRva = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(addressRows, (int)eatIndex * 4, 4));
            if (functionRva == 0) continue;
            // A forwarder points into the export directory rather than at
            // code, so it has no function body to protect.
            if (functionRva >= exportDirRva && functionRva < exportDirRva + 0x10000) continue;
            // Two names may alias the same entry (for example the ANSI and
            // Unicode spellings of one API). Keep the first one so the list
            // stays stable and every row still carries a distinct label.
            if (!map.ContainsKey(functionRva)) map[functionRva] = symbol;
        }
        return map;
    }

    private static string ReadCString(FileStream stream, List<Section> sections, uint rva)
    {
        var section = FindSection(sections, rva);
        if (section is null) return string.Empty;
        var offset = section.Value.RawOffset + (rva - section.Value.VirtualAddress);
        if (offset >= stream.Length) return string.Empty;
        stream.Position = offset;
        var bytes = new List<byte>();
        var buffer = new byte[1];
        while (bytes.Count < 512 && stream.Read(buffer, 0, 1) == 1 && buffer[0] != 0)
        {
            if (buffer[0] < 0x20 || buffer[0] > 0x7E) return string.Empty;
            bytes.Add(buffer[0]);
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    // ------------------------------------------------------------ helpers ----

    private readonly record struct Section(uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics, string Name);

    private static Section? FindSection(List<Section> sections, uint rva)
    {
        foreach (var section in sections)
        {
            var size = Math.Max(section.VirtualSize, section.RawSize);
            if (size == 0) continue;
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + size) return section;
        }
        return null;
    }

    private static string SectionName(ReadOnlySpan<byte> raw)
    {
        var end = raw.IndexOf((byte)0);
        if (end < 0) end = raw.Length;
        if (end == 0) return "?";
        return Encoding.ASCII.GetString(raw[..end].ToArray());
    }

    private static bool DetectStackFrame(FileStream stream, Section section, uint rva)
    {
        var prologue = ReadPrologue(stream, section, rva, 8);
        // push rbp; mov rbp,rsp (x64) / push ebp; mov ebp,esp (x86)
        if (prologue.StartsWith("55-48-89-E5", StringComparison.Ordinal)) return true;
        if (prologue.StartsWith("55-8B-EC", StringComparison.Ordinal)) return true;
        return false;
    }

    private static string ReadPrologue(FileStream stream, Section section, uint rva, int count)
    {
        var offset = section.RawOffset + (rva - section.VirtualAddress);
        if (offset >= stream.Length) return string.Empty;
        stream.Position = offset;
        var bytes = new byte[count];
        var read = stream.Read(bytes, 0, count);
        return string.Join('-', bytes.Take(read).Select(b => b.ToString("X2")));
    }

    private static FunctionScanResult Fail(string error) => new()
    {
        Success = false,
        Error = error,
        Functions = []
    };
}
