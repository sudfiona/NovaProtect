namespace NovaProtect.UI.Services;

/// <summary>
/// English text for the client UI, keyed by the Chinese source string.
///
/// Keys are the exact Chinese literals used in the pages and services, which is
/// the same convention the website uses: adding a translation needs no marker on
/// the element, and a string that has no entry simply renders in Chinese. Keys
/// therefore have to be copied verbatim — punctuation, full-width brackets and
/// leading spaces all matter, and a mismatch shows up as an untranslated label
/// rather than an error.
///
/// Templates keep their <c>{0}</c> placeholders so <see cref="Localizer.F"/> can
/// fill them after translation.
///
/// Deliberately absent: diagnostic-log lines (a support artifact that stays in
/// one language so it stays greppable), the protection core's own stdout (shown
/// verbatim), and release notes (the published record, which must match what
/// GitHub and the website show).
/// </summary>
internal static class LocalizerStrings
{
    internal static readonly Dictionary<string, string> En = new(StringComparer.Ordinal)
    {
        // ---- shell -------------------------------------------------------
        ["工作台"] = "WORKSPACE",
        ["代码保护工作台"] = "Code protection workbench",
        ["保护项目"] = "Protect Project",
        ["对抗与规避"] = "Evasion",
        ["检查工具"] = "Inspector",
        ["运行记录"] = "Activity",
        ["更新日志"] = "Changelog",
        ["设置"] = "Settings",
        ["就绪"] = "Ready",
        ["页面加载失败"] = "Page failed to load",
        ["选择目标、调整策略、构建受保护版本"] =
            "Pick a target, tune the strategy, build a protected release",
        ["静态特征清洗、动态探测与内核探针"] =
            "Static-fingerprint scrubbing, dynamic probes, kernel probes",
        ["读取 PE 信息、水印与虚拟文件清单"] =
            "Read PE information, watermarks and virtual-file lists",
        ["本机保存的保护运行历史"] = "Protection runs saved on this machine",
        ["与 GitHub Releases 同步的版本记录"] = "Release notes synced with GitHub Releases",
        ["外观、语言、更新与数据目录"] = "Appearance, language, updates and data folders",
        ["黑洞"] = "Black Hole",
        ["玻璃"] = "Glass",
        ["波普"] = "Pop",
        ["实验室"] = "Lab",
        ["设置窗口图标失败"] = "Could not set the window icon",

        // ---- shared vocabulary -------------------------------------------
        // One entry per distinct Chinese source: several controls reuse "关闭"
        // (a profile, a level, a toggle's off caption) and all of them read "Off".
        ["关闭"] = "Off",
        ["开启"] = "On",
        ["关"] = "Off",
        ["是"] = "Yes",
        ["否"] = "No",
        ["均衡"] = "Balanced",
        ["激进"] = "Aggressive",
        ["偏执"] = "Paranoid",
        ["基础"] = "Basic",
        ["增强"] = "Enhanced",
        ["严格"] = "Strict",
        ["轻量"] = "Light",
        ["中等"] = "Medium",
        ["高强度"] = "High",
        ["兼容"] = "Compatible",
        ["未知"] = "Unknown",
        ["待识别"] = "Not identified",
        ["项目"] = "Item",
        ["可选"] = "Optional",
        ["2 · 中等"] = "2 · Medium",
        ["1 轮"] = "1 pass",
        ["2 轮"] = "2 passes",
        ["3 轮"] = "3 passes",
        ["常驻"] = "Resident",
        ["全程驻留"] = "Resident throughout",
        ["随机（每次构建不同）"] = "Random (differs every build)",
        ["{0} · 当前"] = "{0} · current",

        // ---- protection page body ----------------------------------------
        ["选择应用、调整保护策略，然后在后台生成受保护版本。"] =
            "Pick an application, tune the protection strategy, then build a protected release in the background.",
        ["等待选择文件"] = "Awaiting a file",
        ["等待有效文件"] = "Awaiting a valid file",
        ["导入项目"] = "Import project",
        ["保存项目"] = "Save project",
        ["导出项目"] = "Export project",
        ["导出当前构建计划"] = "Export the current build plan",
        ["目标文件"] = "Target file",
        ["支持 C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE；也可拖放文件。"] =
            "Accepts x86/x64 EXEs built from C/C++, C#/VB .NET, Rust or Golang; you can also drop a file here.",
        ["输入文件"] = "Input file",
        ["选择需要保护的应用"] = "Choose the application to protect",
        ["输出文件"] = "Output file",
        ["默认生成 *_protected.exe"] = "Defaults to *_protected.exe",
        ["另存为…"] = "Save as…",
        ["使用此文件作为保护目标"] = "Use this file as the protection target",
        ["无效 PE 文件"] = "Not a valid PE file",
        ["已识别目标"] = "Target identified",
        ["无法识别目标"] = "Target not recognised",
        ["保护模式"] = "Protection mode",
        ["模式决定代码处理管线；强度参数仍可单独微调。"] =
            "The mode picks the code pipeline; the intensity parameters can still be tuned individually.",
        ["变异模式"] = "Mutation mode",
        ["虚拟化模式"] = "Virtualisation mode",
        ["Ultra 模式"] = "Ultra mode",
        ["对支持的 x64 代码执行等价变换，通常兼容性更高、体积增长更小。"] =
            "Applies equivalent transforms to supported x64 code; usually more compatible and smaller.",
        ["将已标记的 x64 代码区域转换为自定义 VM 字节码。"] =
            "Converts marked x64 code regions into custom VM bytecode.",
        ["同时启用代码变异与虚拟化，适合需要最高保护等级的 x64 程序。"] =
            "Enables mutation and virtualisation together; for x64 programs that need the highest protection level.",
        ["预设"] = "Preset",
        ["预设只调整已实现能力；构建前会显示请求值与实际生效值。"] =
            "Presets only touch capabilities that exist; the requested and the effective values are both shown before a build.",
        ["变异强度"] = "Mutation strength",
        ["VM 复杂度"] = "VM complexity",
        ["二次虚拟化"] = "Second-level virtualisation",
        ["阶段拆分 + 二级解释器 + 寄存器重映射；仅 x64 生效"] =
            "Stage splitting + guest interpreter + register remapping; x64 only",
        ["嵌套层级"] = "Nesting level",
        ["打开对抗与规避设置"] = "Open the evasion settings",
        ["调整"] = "Adjust",
        ["运行时防护"] = "Runtime protection",
        ["反调试级别"] = "Anti-debug level",
        ["环境检查级别"] = "Environment check level",
        ["内存完整性保护"] = "Memory integrity protection",
        ["导入表保护"] = "Import table protection",
        ["资源区段保护"] = "Resource section protection",
        ["沙箱环境检测"] = "Sandbox detection",
        ["反内存转储"] = "Anti memory dump",
        ["交互桌面环境自检"] = "Interactive desktop self-check",
        ["进程自隔离（拒绝外部读取）"] = "Process self-isolation (deny external reads)",
        ["延时复测抽查（随沙箱检测自动开启）"] = "Delayed re-audit (arms with sandbox detection)",
        ["资源区段加密时会保留程序图标，加密后资源管理器中显示的图标与原文件一致。"] =
            "Encrypting the resource section keeps the program icon, so Explorer shows the same icon as the original file.",
        ["输出处理"] = "Output handling",
        ["区段压缩"] = "Section packing",
        ["区段加密"] = "Section encryption",
        ["移除调试目录"] = "Strip the debug directory",
        ["裁剪重定位并关闭 ASLR"] = "Strip relocations and disable ASLR",
        ["裁剪导出目录"] = "Strip the export directory",
        ["重定位/导出裁剪仅用于原生 EXE；.NET EXE 采用 CLR 安全封装并跳过破坏 CLR 契约的选项。导入虚拟化使用运行时 IAT 重建。"] =
            "Relocation and export stripping apply to native EXEs only; a .NET EXE takes the CLR safe wrapper and skips options that would break the CLR contract. Import virtualisation rebuilds the IAT at run time.",
        ["许可、标识与虚拟文件"] = "Licence, identity and virtual files",
        ["这些内容会随受保护文件写入元数据或虚拟文件容器。"] =
            "These are written into the protected file's metadata or its virtual-file container.",
        ["添加虚拟文件"] = "Add virtual files",
        ["水印"] = "Watermark",
        ["可选的产品或构建标识"] = "Optional product or build identifier",
        ["许可密钥"] = "Licence key",
        ["激活/硬件绑定（一机一码）"] = "Activation / hardware binding (one machine, one code)",
        ["16 位机器 ID 或 auto"] = "16-character machine ID, or auto",
        ["读取本机 ID"] = "Read local machine ID",
        ["能力边界"] = "Capability boundary",
        ["许可和激活绑定由 x64 保护运行时执行。可在检查工具中读取本机激活 ID；auto 绑定构建机。内部核心不支持直接命令调用。"] =
            "Licensing and activation binding are enforced by the x64 protection runtime. The machine activation ID can be read in the Inspector; auto binds to the build machine. The internal core does not accept direct command invocation.",
        ["尚未添加虚拟文件"] = "No virtual files added yet",
        ["移除选中项"] = "Remove selected",
        ["函数 / 区域对象编辑器"] = "Function / region object editor",
        ["SDK marker 区域直接来自目标文件中的 NovaProtect BEGIN/END 字节模式；任意函数的扫描与勾选请使用下方「函数保护」面板。"] =
            "SDK marker regions come straight from the NovaProtect BEGIN/END byte patterns in the target; use the Function protection panel below to scan and tick arbitrary functions.",
        ["重新扫描 marker"] = "Rescan markers",
        ["等待目标"] = "Awaiting a target",
        ["选择 PE 后读取 SDK marker。"] = "Choose a PE to read its SDK markers.",
        ["显示名称"] = "Display name",
        ["对象模式"] = "Object mode",
        ["继承全局模式"] = "Inherit global mode",
        ["跳过此 marker 区域"] = "Skip this marker region",
        ["Ultra（VM + 前置变异）"] = "Ultra (VM + leading mutation)",
        ["此区域要求启用全局激活绑定"] = "This region requires global activation binding",
        ["函数保护（VMP 式扫描）"] = "Function protection (VMP-style scan)",
        ["扫描目标文件的函数表，勾选加入 VM 保护；也可一键添加所有可虚拟化函数。函数级保护与 SDK marker 区域可同时使用。"] =
            "Scan the target's function table and tick functions for VM protection, or add every virtualisable function at once. Function-level protection and SDK marker regions can be used together.",
        ["扫描函数"] = "Scan functions",
        ["选择 x64/x86 PE 后扫描函数表（x64 读取 .pdata 异常目录）。"] =
            "Choose an x64/x86 PE to scan its function table (x64 reads the .pdata exception directory).",
        ["全部函数"] = "All functions",
        ["仅可虚拟化"] = "Virtualisable only",
        ["仅导出函数"] = "Exported only",
        ["仅已勾选"] = "Ticked only",
        ["批量操作"] = "Bulk actions",
        ["全选"] = "Select all",
        ["反选"] = "Invert",
        ["添加所有函数"] = "Add all functions",
        ["清除勾选"] = "Clear ticks",
        ["「添加所有函数」会勾选全部可虚拟化函数（无栈帧且容量足够）；VM 运行时会自动跳过无法翻译的函数并保持原生执行。"] =
            "'Add all functions' ticks every virtualisable function (no stack frame, large enough); at run time the VM skips anything it cannot translate and leaves it native.",
        ["批量应用到勾选函数"] = "Apply in bulk to ticked functions",
        ["仅前置变异"] = "Leading mutation only",
        ["跳过此函数"] = "Skip this function",
        ["勾选函数要求启用全局激活绑定"] = "Ticked functions require global activation binding",
        ["应用到勾选函数"] = "Apply to ticked functions",
        ["尚未勾选函数。"] = "No functions ticked yet.",
        ["尚未勾选函数。函数级保护与 SDK marker 区域可同时使用。"] =
            "No functions ticked yet. Function-level protection and SDK marker regions can be used together.",
        ["当前目标能力"] = "Current target capabilities",
        ["当前文件的精确执行路径和冲突；状态来自实际核心能力与 PE 类型。"] =
            "The exact execution path and conflicts for this file; states come from the real core capabilities and the PE type.",
        ["准备就绪"] = "Ready",
        ["请求配置将在开始前解析。"] = "The requested configuration is resolved before the build starts.",
        ["开始保护"] = "Start protection",
        ["实时日志"] = "Live log",
        ["清空"] = "Clear",
        ["取消"] = "Cancel",
        ["确定"] = "OK",
        ["好"] = "OK",

        // ---- evasion page body -------------------------------------------
        ["控制静态特征清洗、反分析探测与内核驱动探针。这些设置对保护项目页的每次运行生效。"] =
            "Controls static-fingerprint scrubbing, anti-analysis probes and kernel driver probes. These settings apply to every run started from the Protect Project page.",
        ["规避档位"] = "Evasion profile",
        ["档位展开明细"] = "Profile details",
        ["构建签名种子"] = "Build signature seed",
        ["种子决定标签、nonce、节区后缀、填充与探测顺序。留空则每次构建从系统熵取新值；填入固定值可复现同一构建。"] =
            "The seed drives labels, nonces, section suffixes, padding and probe order. Leave it empty and every build draws fresh system entropy; a fixed value reproduces the same build.",
        ["留空 = 随机；或填 1-16 位十六进制"] = "Empty = random; or 1-16 hex digits",
        ["生成"] = "Generate",
        ["复制"] = "Copy",
        ["每次构建重新随机"] = "Reseed on every build",
        ["已开启：忽略种子，重新取熵"] = "On: ignore the seed and draw fresh entropy",
        ["已关闭：按种子复现"] = "Off: reproduce from the seed",
        ["动态对抗"] = "Dynamic evasion",
        ["运行期探测强度。级别越高越容易识别分析环境，也越容易在真实用户机器上误触发。"] =
            "Run-time probe intensity. Higher levels identify an analysis environment more reliably and also misfire more often on real user machines.",
        ["垃圾指令密度"] = "Junk instruction density",
        ["每个注入点插入的垃圾指令块数量。0 表示不插入。"] =
            "Junk blocks injected per site. 0 inserts none.",
        ["反沙箱级别"] = "Anti-sandbox level",
        ["驱动加权沙箱评分。需配合沙箱阈值使用。"] =
            "Drives the weighted sandbox score. Used together with the sandbox threshold.",
        ["内存流式解密"] = "Streamed memory decryption",
        ["驻留（不解密流）"] = "Resident (no decryption stream)",
        ["加密区按需解密的密钥流轮数。轮数越多，内存快照越难直接还原。"] =
            "Keystream passes over encrypted regions, decrypted on demand. More passes make a memory snapshot harder to reconstruct directly.",
        ["引爆延迟"] = "Detonation delay",
        ["执行前等待时长。分析沙箱通常只观察很短时间，真实用户几乎感觉不到。0 表示不等待。"] =
            "How long to wait before executing. Analysis sandboxes usually watch for a very short time and a real user barely notices. 0 waits not at all.",
        ["API 反挂钩"] = "API unhooking",
        ["已开启：还原磁盘 ntdll 文本并扫描 IAT 重定向"] =
            "On: restore the on-disk ntdll text and sweep the IAT for redirects",
        ["已关闭：保留系统当前挂钩状态"] = "Off: keep the system's current hook state",
        ["内核与 hypervisor"] = "Kernel and hypervisor",
        ["驱动级探针与 hypervisor 存在性判定。两者都不信任对方自报的标志位，改用可测量的行为差异。"] =
            "Driver-level probes and hypervisor presence checks. Neither trusts a self-reported flag; both use measurable behavioural differences instead.",
        ["驱动探针层级"] = "Driver probe level",
        ["CPUID 退出代价探测"] = "CPUID exit-cost probe",
        ["已开启：用 16 次串行 CPUID 的耗时差判定 hypervisor"] =
            "On: 16 serialised CPUIDs; the timing delta reveals a hypervisor",
        ["已关闭：只信 CPUID 厂商叶子"] = "Off: trust the CPUID vendor leaf only",
        ["审计本机 hypervisor"] = "Audit the local hypervisor",
        ["审计本机内核工件"] = "Audit local kernel artifacts",
        ["审计只读取本机状态并打印结论，不改动任何文件，也不需要管理员权限。"] =
            "The audit only reads local state and prints a verdict. It changes no files and needs no administrator rights.",
        ["环境闸门"] = "Environment gate",
        ["判定是否在沙箱或无头环境中运行。分数达到阈值即拒绝执行。阈值越低越严格，也越容易误杀低配真机。"] =
            "Decides whether the program runs in a sandbox or headless environment. A score reaching the threshold refuses to execute. A lower threshold is stricter and also more likely to refuse a real low-end machine.",
        ["沙箱分数阈值"] = "Sandbox score threshold",
        ["无头环境分数阈值"] = "Headless score threshold",
        ["硬件下限（0 = 不检查）"] = "Hardware minimums (0 = no check)",
        ["逻辑处理器数"] = "Logical processors",
        ["物理内存 (MB)"] = "Physical memory (MB)",
        ["系统运行时长 (ms)"] = "System uptime (ms)",
        ["屏幕宽度"] = "Screen width",
        ["屏幕高度"] = "Screen height",
        ["显示器数量"] = "Monitor count",
        ["环境闸门只在保护项目页开启“沙箱防护”或“环境检查”时生效；否则这些阈值会被记录但不参与判定。"] =
            "The environment gate only applies when Sandbox detection or Environment check is on in the Protect Project page; otherwise these thresholds are recorded but not evaluated.",
        ["审计输出"] = "Audit output",
        ["保存设置"] = "Save settings",
        ["恢复默认"] = "Restore defaults",

        // ---- settings page -----------------------------------------------
        ["外观"] = "Appearance",
        ["从黑洞、玻璃、波普和实验室中选择客户端外观。"] =
            "Choose between Black Hole, Glass, Pop and Lab.",
        ["视觉主题"] = "Visual theme",
        ["立即生效并记住选择。"] = "Applies immediately and remembers your choice.",
        ["黑洞（默认）"] = "Black Hole (default)",
        ["液态玻璃"] = "Liquid glass",
        ["新波普"] = "Neo pop",
        ["暗色实验室"] = "Dark lab",
        ["界面语言"] = "Interface language",
        ["只影响客户端界面文字，不改变构建行为。默认跟随已保存的设置。"] =
            "Affects client UI text only; build behaviour is unchanged. Follows the saved preference.",
        ["简体中文"] = "Simplified Chinese",
        ["英语"] = "English",
        ["关于 NovaProtect"] = "About NovaProtect",
        ["WinUI 3 · HyperOS 柔光玻璃客户端"] = "WinUI 3 · HyperOS soft-glass client",
        ["与官网 nova.fbi.plus 同一设计语言"] = "Same design language as nova.fbi.plus",
        ["用于保护您拥有合法授权的软件。请在发布前对目标程序执行完整兼容性和安全性测试。"] =
            "Use only on software you are licensed to protect. Run full compatibility and security testing on the target before release.",
        ["客户端不需要账户登录；官网仅提供安装包下载与版本发布。"] =
            "The client requires no account; the website only serves installers and release notes.",
        ["数据与诊断"] = "Data & diagnostics",
        ["全部保存在本机，不上传任何服务器。"] =
            "Everything stays on this machine; nothing is uploaded.",
        ["打开日志目录"] = "Open log folder",
        ["打开配置目录"] = "Open config folder",
        ["恢复默认规避设置"] = "Reset evasion settings",
        ["只重置对抗与规避设置，不影响项目文件和历史记录。"] =
            "Resets evasion settings only; project files and history are untouched.",
        ["在线更新"] = "Online update",
        ["从官网 client-updates 清单读取已发布版本"] =
            "Reads published builds from the website client-updates feed",
        ["更新状态"] = "Update status",
        ["尚未检查更新。"] = "No update check has run yet.",
        ["检查更新"] = "Check for updates",
        ["下载更新"] = "Download update",
        ["运行安装包"] = "Run installer",
        ["外观设置立即生效；在线更新从官网读取已发布的客户端版本。"] =
            "Appearance changes apply immediately; online update reads published client builds from the website.",

        // ---- settings code-behind ----------------------------------------
        ["规避设置已恢复默认。"] = "Evasion settings restored to defaults.",
        ["对抗与规避的档位、种子、探测强度和环境闸门都会回到默认值。已保存的项目文件不受影响。"] =
            "The evasion profile, seed, probe strength and environment gate all return to their defaults. Saved projects are untouched.",
        ["正在读取更新信息…"] = "Reading update information…",
        ["正在检查更新…"] = "Checking for updates…",
        ["正在下载并校验更新…"] = "Downloading and verifying the update…",
        ["更新失败："] = "Update failed: ",
        ["更新下载失败。"] = "The update download failed.",
        ["更新信息暂时不可用。"] = "Update information is unavailable right now.",
        ["检查更新失败："] = "Update check failed: ",
        ["无法打开目录："] = "Could not open the folder: ",
        ["当前版本 {0} 已是最新版本。"] =
            "Version {0} is already the latest.",
        ["发现客户端 {0}，大小 {1}。下载后会再次校验 SHA-256。"] =
            "Client {0} is available ({1}). Its SHA-256 will be verified again after download.",
        ["已完成 {0} 的大小和 SHA-256 校验。"] =
            "{0} passed the size and SHA-256 checks.",
        ["安装包路径异常，已拒绝启动。"] =
            "The installer path is not valid, so it was not started.",
        ["安装程序已启动，请按向导完成升级。"] =
            "The installer has started; follow the wizard to finish upgrading.",
        ["无法启动已校验的安装程序。"] = "Could not start the verified installer.",
        ["已校验的安装包不存在，请重新下载。"] =
            "The verified installer is gone; download it again.",
        ["诊断日志：（初始化失败）"] = "Diagnostic log: (initialisation failed)",
        ["诊断日志：{0}\n规避设置：{1}\\evasion.json"] =
            "Diagnostic log: {0}\nEvasion settings: {1}\\evasion.json",

        // ---- dialogs and log text -----------------------------------------
        ["保存规避设置失败"] = "Could not save the evasion settings",
        ["读取规避设置失败，改用默认值"] =
            "Could not read the evasion settings; using defaults",
        ["项目文件为空或格式无效"] = "The project file is empty or malformed",
        ["不支持的项目 SchemaVersion {0}；当前版本支持 1..{1}"] =
            "Unsupported project SchemaVersion {0}; this build supports 1..{1}",
        ["{0} 个字符"] = "{0} characters",
        ["较早的 {0} 行"] = "{0} earlier lines",
        ["… 已省略"] = "… omitted",
        ["，仅保留最近内容 …\\n"] = ", keeping only the most recent output …\n",
        ["、"] = ", ",
        ["无"] = "None",

        // ---- activity page ------------------------------------------------
        ["记录保存在本机，直到你手动删除。"] =
            "Records stay on this machine until you delete them.",
        ["清空记录"] = "Clear records",
        ["清空运行记录"] = "Clear activity",
        ["删除该条记录"] = "Delete this record",
        ["完成一次保护后，结果会出现在这里。"] =
            "Results appear here once you finish a protection run.",
        ["暂无保护记录"] = "No protection runs yet",
        ["清空运行记录？"] = "Clear activity?",
        ["已保存的保护成功、失败和取消记录都会删除。"] =
            "Saved successful, failed and cancelled runs will all be deleted.",

        // ---- changelog page ----------------------------------------------
        ["当前版本"] = "Current version",
        ["刷新"] = "Refresh",
        ["与 GitHub Releases 同步；离线时显示随程序打包的版本记录。"] =
            "Synced with GitHub Releases; offline it shows the notes bundled with this build.",
        ["在 GitHub 查看完整说明"] = "Read the full notes on GitHub",
        ["暂无更新记录"] = "No release notes yet",
        ["预发布"] = "Pre-release",
        ["正在读取 GitHub 发布历史…"] = "Reading GitHub release history…",
        ["显示的是随程序打包的版本记录"] = "Showing the release notes bundled with this build",
        [" 联网后按「刷新」可读取完整发布历史。"] =
            " Connect to the network and press Refresh to load the full release history.",
        ["…（共 {0} 行，完整说明见下方 GitHub 链接）"] =
            "… ({0} lines in total; the full notes are behind the GitHub link below)",

        // ---- inspect page -------------------------------------------------
        ["PE 信息"] = "PE information",
        ["本机 ID"] = "Machine ID",
        ["读取 PE 信息、嵌入水印和虚拟文件清单，不修改目标文件。"] =
            "Read PE information, embedded watermark and virtual-file lists without modifying the target.",
        ["读取水印"] = "Read watermark",
        ["检查结果"] = "Results",
        ["目标与操作"] = "Target and actions",
        ["虚拟文件"] = "Virtual files",
        ["选择要检查的文件"] = "Choose a file to inspect",
        ["只读检查，不会写回 PE"] = "Read-only check; the PE is never written back",
        ["浏览…"] = "Browse…",
        ["选择文件"] = "Choose file",
        ["请选择有效文件。"] = "Choose a valid file.",
        ["正在读取…"] = "Reading…",
        ["正在检查…"] = "Inspecting…",

        // ---- shared option labels ----------------------------------------
        ["不保护"] = "No protection",
        ["变异"] = "Mutation",
        ["虚拟化"] = "Virtualisation",
        ["虚拟化+变异"] = "Virtualisation + mutation",
        ["PE 函数扫描"] = "PE function scan",
        ["{0} · {1} · {2} 字节"] = "{0} · {1} · {2} bytes",

        // ---- evasion page code-behind -------------------------------------
        ["关闭：不生成任何内核探针，受保护程序不会触碰驱动层。"] =
            "Off: no kernel probes are generated and the protected program never touches the driver layer.",
        ["仅工件：释放驱动工件并做静态特征，不做运行期探测。"] =
            "Artifacts only: the driver artifact is shipped with static fingerprints and no run-time probing.",
        ["加 KUSER_SHARED_DATA tick 连续性：用不经过系统调用的时间源识别内核层插桩。"] =
            "Adds KUSER_SHARED_DATA tick continuity: a time source that never enters a syscall reveals kernel-level instrumentation.",
        ["全开：在上一层基础上加入全部探针，包括驱动自摘链。兼容性风险最高。"] =
            "Everything on: every probe from the level below plus the driver self-unlink chain. Highest compatibility risk.",
        ["种子格式无效"] = "Invalid seed format",
        ["种子必须是 1-16 位十六进制且不等于 0。留空表示每次构建随机。"] =
            "The seed must be 1-16 hex digits and not zero. Leave it empty for a random seed each build.",
        ["种子必须是 1-16 位十六进制且不等于 0，或者留空表示每次构建随机。"] =
            "The seed must be 1-16 hex digits and not zero, or empty for a random seed each build.",
        ["档位与逐项设置有冲突"] = "The profile conflicts with the per-item settings",
        ["规避档位为「关闭」时，引擎不装配动态规避与沙箱评分，即使填了反沙箱级别也不生效。需要该效果请至少选「均衡」；垃圾指令密度走虚拟化通道，不受档位影响。"] =
            "With the profile set to Off the engine assembles no dynamic evasion and no sandbox scoring, so an anti-sandbox level has no effect. Pick at least Balanced for that; junk density travels on the virtualisation channel and is unaffected by the profile.",
        ["本次构建将从系统熵取新种子。"] = "This build will draw a fresh seed from system entropy.",
        ["留空时引擎自身也会取熵，两次构建不会相同。"] =
            "Left empty, the engine draws entropy itself, so two builds never match.",
        ["固定种子 {0}：同一输入会得到完全相同的构建，便于复现问题。"] =
            "Fixed seed {0}: the same input produces an identical build, which makes a problem reproducible.",
        ["种子格式无效，保存会被拒绝。"] = "The seed format is invalid, so saving will be refused.",
        ["当前闸门："] = "Current gate: ",
        ["。"] = ".",
        ["。未设置硬件下限，只看分数阈值。"] =
            ". No hardware minimums are set, so only the score thresholds apply.",
        ["先在左侧生成或填一个种子。"] = "Generate or type a seed on the left first.",
        ["已保存"] = "Saved",
        ["对抗与规避设置已保存，保护项目页的下一次运行立即生效。"] =
            "Evasion settings saved; they take effect on the next run from the Protect Project page.",
        ["已恢复默认"] = "Defaults restored",
        ["规避档位回到「均衡」，环境闸门回到引擎默认阈值。"] =
            "The evasion profile is back to Balanced and the environment gate is back to the engine defaults.",
        ["hypervisor 审计"] = "hypervisor audit",
        ["内核工件审计"] = "kernel artifact audit",
        ["正在执行{0}…"] = "Running the {0}…",
        ["{0}完成，但没有返回内容。"] = "{0} finished but returned nothing.",
        ["{0}失败：{1}"] = "{0} failed: {1}",

        // ---- evasion models ------------------------------------------------
        ["规避已关闭：受保护程序带有正常的静态特征。"] =
            "Evasion is off: the protected program keeps normal static fingerprints.",
        ["垃圾指令 {0}/8 · 反沙箱 {1}/3 · 内核 {2}/3"] =
            "Junk {0}/8 · anti-sandbox {1}/3 · kernel {2}/3",
        ["反沙箱评分级别"] = "Anti-sandbox score level",
        ["内核探针级别"] = "Kernel probe level",
        ["预执行延迟"] = "Pre-execution delay",
        ["内存流式解密轮数"] = "Streamed decryption passes",
        ["单次解密窗口"] = "Decryption window",
        ["IAT 钩子扫描"] = "IAT hook scan",
        ["诱饵字符串"] = "Decoy strings",
        ["驱动自摘链"] = "Driver self-unlink chain",
        ["预置拦截阈值（可覆盖）"] = "Preset block threshold (overridable)",
        ["静态特征清洗（Rich / 时间戳 / 节区名 / PDB / 填充 / 签名）"] =
            "Static-fingerprint scrub (Rich / timestamp / section names / PDB / padding / signature)",
        ["加载器分区布局 · 禁止 RWX 页"] = "Loader partitioned layout · no RWX pages",
        ["用户输入闸门 · RDTSC/CPUID 时序"] = "User-input gate · RDTSC/CPUID timing",
        ["hypervisor 厂商探测 · 时间侧信道"] = "Hypervisor vendor probe · timing side channel",
        ["ntdll 文本还原 · 内核导出哈希解析"] = "ntdll text restore · kernel export hash resolution",
        ["{0}：关闭 {1}，均衡 {2}，激进 {3}，偏执 {4}"] =
            "{0}: Off {1}, Balanced {2}, Aggressive {3}, Paranoid {4}",
        ["不做任何规避。生成的程序带完整静态特征，适合本地调试或需要被安全软件正常识别的场景。"] =
            "No evasion at all. The generated program keeps its full static fingerprint, which suits local debugging or cases where security software should recognise it normally.",
        ["轻档：只做静态清洗 + 单层动态探测。垃圾指令 1/8、反沙箱 1 级、延迟 1.5 s、内存解密 1 轮、内核仅工件。不启用 CPUID 退出成本与 IAT 钩子扫描——兼容性优先。"] =
            "Light: static scrubbing plus a single dynamic stage. Junk 1/8, anti-sandbox level 1, 1.5 s delay, one decryption pass, driver artifacts only. The CPUID exit-cost probe and the IAT hook scan stay off — compatibility first.",
        ["中档：在均衡之上把每项探测加深一档。垃圾指令 3/8、反沙箱与反调试各 2 级、延迟 3 s、内存解密 2 轮、内核 2 级，并新增 CPUID 退出成本探测、IAT 钩子扫描与诱饵字符串。"] =
            "Medium: every probe one step deeper than Balanced. Junk 3/8, anti-sandbox and anti-debug at level 2, 3 s delay, two decryption passes, kernel level 2, plus the CPUID exit-cost probe, the IAT hook scan and decoy strings.",
        ["重档：各项拉到引擎上限。垃圾指令 5/8、反沙箱与反调试各 3 级、延迟 5 s、内存解密 3 轮且窗口缩到 2048 B、内核 3 级并启用驱动自摘链，预置拦截阈值同时收紧到 30。兼容性风险最高，发布前必须在目标环境实测。"] =
            "Heavy: every knob at the engine ceiling. Junk 5/8, anti-sandbox and anti-debug at level 3, 5 s delay, three decryption passes with the window down to 2048 B, kernel level 3 with the driver self-unlink chain, and the preset block threshold tightened to 30. Highest compatibility risk — test in the target environment before release.",
        ["沙箱阈值 {0}"] = "sandbox threshold {0}",
        ["环境阈值 {0}"] = "environment threshold {0}",
        ["{0} 核"] = "{0} cores",
        ["运行 {0} ms"] = "uptime {0} ms",
        ["{0} 显示器"] = "{0} monitors",

        // ---- protection page code-behind ----------------------------------
        ["环境闸门："] = "Environment gate: ",
        ["环境闸门未启用：打开「沙箱防护」或「环境检查」后才按阈值判定。"] =
            "Environment gate not active: thresholds are only evaluated once Sandbox detection or Environment check is on.",
        ["Windows 可执行文件"] = "Windows executable",
        ["读取本机 ID 失败"] = "Could not read the local machine ID",
        ["已读取本机激活 ID：{0}（已填入激活/硬件绑定框）"] =
            "Read local activation ID: {0} (filled into the activation / hardware binding box)",
        ["构建配置存在冲突"] = "The build configuration has conflicts",
        ["—— {0} 开始保护 ——"] = "—— protection started {0} ——",
        ["输入: {0}"] = "Input: {0}",
        ["输出: {0}"] = "Output: {0}",
        ["规避: {0} · {1}"] = "Evasion: {0} · {1}",
        ["构建计划: {0}"] = "Build plan: {0}",
        ["正在准备保护管线…"] = "Preparing the protection pipeline…",
        ["命令行: "] = "Command line: ",
        ["保护完成"] = "Protection finished",
        ["完成：已生成受保护文件。"] = "Done: the protected file was generated.",
        ["输出文件已生成：\n{0}"] = "Output written:\n{0}",
        ["已取消"] = "Cancelled",
        ["保护失败"] = "Protection failed",
        ["保护已取消"] = "Protection cancelled",
        ["请选择有效文件"] = "Choose a valid file",
        ["输入文件不存在或无法访问。"] = "The input file does not exist or cannot be read.",
        ["文件格式无效"] = "Invalid file format",
        ["目标不是可识别的 Windows PE 文件。"] = "The target is not a recognisable Windows PE file.",
        ["请选择 EXE 程序"] = "Choose an EXE program",
        ["NovaProtect {0} 的正式输入范围是由 C/C++、C#/VB .NET、Rust 或 Golang 生成的 EXE。"] =
            "NovaProtect {0} officially accepts EXEs built from C/C++, C#/VB .NET, Rust or Golang.",
        ["请选择输出位置"] = "Choose an output location",
        ["输出文件路径不能为空。"] = "The output path cannot be empty.",
        ["输出路径无效"] = "Invalid output path",
        ["为了避免覆盖原文件，输出路径必须与输入路径不同。"] =
            "To avoid overwriting the original, the output path must differ from the input path.",
        ["构建签名种子无效"] = "Invalid build signature seed",
        ["当前种子是「{0}」，不是 1-16 位十六进制或值为零。请到「对抗与规避」页重新生成，或清空让引擎自行取熵。"] =
            "The current seed is \"{0}\", which is not 1-16 hex digits or evaluates to zero. Regenerate it on the Evasion page, or clear it so the engine draws its own entropy.",
        ["VM 复杂度为 0"] = "VM complexity is 0",
        ["当前模式请求虚拟化，但 VM 复杂度为 0。请提高复杂度，或切换到变异模式。"] =
            "The current mode asks for virtualisation but VM complexity is 0. Raise the complexity or switch to mutation mode.",
        ["未发现 SDK marker"] = "No SDK markers found",
        ["发现 {0} 个 SDK marker 区域"] = "Found {0} SDK marker regions",
        ["对象编辑器保持为空；不会用导出、符号或反编译结果伪装成可保护对象。"] =
            "The object editor stays empty; exports, symbols or decompiler output are never passed off as protectable objects.",
        ["对象列表直接来自 NovaProtect SDK marker 的字节模式和 RVA 边界。"] =
            "The object list comes straight from the NovaProtect SDK marker byte patterns and RVA bounds.",
        ["函数扫描失败"] = "Function scan failed",
        ["扫描到 {0} 个函数"] = "Scanned {0} functions",
        ["{0}；可虚拟化 {1} 个。 VM 运行时会对无法翻译的函数自动回退原生执行。"] =
            "{0}; {1} are virtualisable. At run time the VM automatically falls back to native execution for anything it cannot translate.",
        ["批量应用：没有勾选的函数。"] = "Bulk apply: no functions are ticked.",
        ["批量应用：已更新 {0} 个勾选函数的保护参数。"] =
            "Bulk apply: updated the protection parameters of {0} ticked functions.",
        ["已勾选 {0} 个函数（其中 {1} 个满足 VM 前置条件），合计 {2}。"] =
            "{0} functions ticked ({1} meet the VM preconditions), {2} in total.",
        [" 含栈帧或过小的函数会由 VM 运行时自动跳过并保持原生执行。"] =
            " Functions with a stack frame, or too small, are skipped by the VM at run time and stay native.",
        ["来源 {0}；marker RVA 0x{1:X8}；区域 {2}；{3} 字节"] =
            "Source {0}; marker RVA 0x{1:X8}; region {2}; {3} bytes",
        ["NovaProtect 项目"] = "NovaProtect project",
        ["项目已保存: {0}"] = "Project saved: {0}",
        ["项目已导入: {0}"] = "Project imported: {0}",
        ["项目导入失败"] = "Project import failed",
        ["构建计划已导出: {0}"] = "Build plan exported: {0}",

        // ---- build plan capability names -----------------------------------
        ["导入虚拟化"] = "Import virtualisation",
        ["资源保护"] = "Resource protection",
        ["内存完整性"] = "Memory integrity",
        ["进程自隔离/反读取"] = "Process self-isolation / anti-read",
        ["延时复测抽查"] = "Delayed re-audit",
        ["调试目录裁剪"] = "Debug directory strip",
        ["重定位裁剪"] = "Relocation strip",
        ["导出裁剪"] = "Export strip",
        ["运行时许可"] = "Runtime licence",
        ["激活/硬件绑定"] = "Activation / hardware binding",
        ["marker VM {0}"] = "marker VM {0}",
        ["二次虚拟化 level {0}"] = "Second-level virtualisation level {0}",
        ["marker 变异 {0}"] = "marker mutation {0}",
        ["反调试 {0}"] = "Anti-debug {0}",
        ["环境检查 {0}"] = "Environment check {0}",
        ["尚未选择有效 PE 目标"] = "No valid PE target selected yet",
        ["当前保护核心没有 ARM64 loader；拒绝生成伪兼容输出"] =
            "The current protection core has no ARM64 loader, so it refuses to emit a falsely compatible output",
        ["当前版本只接受 C#/VB .NET EXE；托管 DLL 不进入 EXE 保护封装流程"] =
            "This build accepts C#/VB .NET EXE only; a managed DLL does not go through the EXE protection wrapper",
        ["当前保护核心只接受 x86/x64 EXE（C/C++、C#/VB .NET、Rust、Golang）"] =
            "The current protection core accepts x86/x64 EXE only (C/C++, C#/VB .NET, Rust, Golang)",
        [".NET EXE CLR 安全封装"] = ".NET EXE CLR safe wrapper",
        ["托管载荷加密"] = "Managed payload encryption",
        ["封装载荷完整性"] = "Wrapper payload integrity",
        ["启动器反调试 {0}"] = "Launcher anti-debug {0}",
        ["启动器环境检查 {0}"] = "Launcher environment check {0}",
        ["启动器反沙箱门禁"] = "Launcher anti-sandbox gate",
        ["启动器反转储门禁"] = "Launcher anti-dump gate",
        ["启动器交互桌面上限"] = "Launcher interactive-desktop ceiling",
        ["运行时许可门禁"] = "Runtime licence gate",
        ["激活/硬件绑定门禁"] = "Activation / hardware binding gate",
        ["导入虚拟化（CLR 启动契约必须保留）"] =
            "Import virtualisation (the CLR start-up contract has to stay intact)",
        ["资源保护（托管资源保持在封装载荷中）"] =
            "Resource protection (managed resources stay inside the wrapper payload)",
        ["调试目录裁剪（不重写托管 PE）"] =
            "Debug directory strip (the managed PE is not rewritten)",
        ["重定位裁剪（CLR 封装模式不修改原 PE）"] =
            "Relocation strip (CLR wrapper mode leaves the original PE alone)",
        ["导出裁剪（CLR 封装模式不修改原 PE）"] =
            "Export strip (CLR wrapper mode leaves the original PE alone)",
        ["marker VM/变异与函数 VM（仅原生 x64）"] =
            "marker VM / mutation and function VM (native x64 only)",
        ["二次虚拟化（仅原生 x64）"] = "Second-level virtualisation (native x64 only)",
        ["进程自隔离（CLR 封装载荷以子进程启动）"] =
            "Process self-isolation (the CLR wrapper payload starts as a child process)",
        ["延时复测（CLR 封装无原生复查钩子）"] =
            "Delayed re-audit (the CLR wrapper has no native recheck hook)",
        ["水印（不重写托管资源）"] = "Watermark (managed resources are not rewritten)",
        ["区段加密（需要启用区段打包）"] = "Section encryption (requires section packing)",
        ["导入虚拟化（运行时 IAT 重建）"] = "Import virtualisation (IAT rebuilt at run time)",
        ["DLL 导出裁剪会移除对外入口，当前目标是 DLL"] =
            "Export stripping on a DLL removes its public entry points, and the target is a DLL",
        ["DLL 不能可靠固定到首选基址，禁止裁剪重定位"] =
            "A DLL cannot be pinned reliably to its preferred base, so relocation stripping is refused",
        ["{0} 个扫描函数 VM"] = "{0} scanned functions VM",
        ["函数/区域保护（目标中没有 NovaProtect SDK marker 或勾选函数）"] =
            "Function / region protection (the target has no NovaProtect SDK marker and no ticked functions)",
        ["{0} 个 marker 区域 VM"] = "{0} marker regions VM",
        ["marker VM（所有已发现对象均配置为跳过）"] =
            "marker VM (every discovered object is configured to be skipped)",
        ["VM 前置变异"] = "VM leading mutation",
        ["独立原生变异（当前只实现 VM 前置变异）"] =
            "Standalone native mutation (only leading mutation is implemented)",
        ["marker VM（仅原生 x64）"] = "marker VM (native x64 only)",
        ["marker 变异（仅原生 x64 VM 管线）"] = "marker mutation (native x64 VM pipeline only)",
        ["x86 loader 内存完整性"] = "x86 loader memory integrity",
        ["运行时许可仅支持原生 x64"] = "Runtime licensing supports native x64 only",
        ["激活/硬件绑定仅支持原生 x64"] = "Activation / hardware binding supports native x64 only",
        ["x86 loader 反调试 {0}"] = "x86 loader anti-debug {0}",
        ["x86 loader 环境检查 {0}"] = "x86 loader environment check {0}",
        ["反沙箱检测（x86 stub 未接 NPP1 评分门）"] =
            "Sandbox detection (the x86 stub has no NPP1 scoring gate)",
        ["反内存转储（x86 stub 未接 NPP1 反转储）"] =
            "Anti memory dump (the x86 stub has no NPP1 anti-dump)",
        ["交互桌面环境自检（x86 stub 未接 NPP1 环境门）"] =
            "Interactive desktop self-check (the x86 stub has no NPP1 environment gate)",
        ["进程自隔离（x86 stub 未接 NPP1 自隔离）"] =
            "Process self-isolation (the x86 stub has no NPP1 self-isolation)",
        ["延时复测（x86 stub 未接 NPP1 复查钩子）"] =
            "Delayed re-audit (the x86 stub has no NPP1 recheck hook)",
        ["函数规则 {0} 不是受信任的函数扫描来源"] =
            "Function rule {0} does not come from a trusted function scan",
        ["函数规则 {0} 的 RVA 范围无效"] = "Function rule {0} has an invalid RVA range",
        ["函数规则 {0} 请求 VM，但全局模式未启用虚拟化"] =
            "Function rule {0} asks for the VM but the global mode does not enable virtualisation",
        ["函数规则 {0} 请求激活锁定，但未配置激活绑定"] =
            "Function rule {0} asks for activation locking but no activation binding is configured",
        ["对象规则 {0} 不是受信任的 NovaProtect SDK marker 来源"] =
            "Object rule {0} does not come from a trusted NovaProtect SDK marker",
        ["对象规则 {0} 不匹配当前文件 marker"] =
            "Object rule {0} matches no marker in the current file",
        ["对象规则 {0} 请求 VM，但全局模式未启用虚拟化"] =
            "Object rule {0} asks for the VM but the global mode does not enable virtualisation",
        ["对象规则 {0} 请求激活锁定，但未配置激活绑定"] =
            "Object rule {0} asks for activation locking but no activation binding is configured",
        ["{0} 项"] = "{0} items",
        ["PE 结构重建"] = "PE structure rebuild",
        ["requested: {0}。effective: {1}。skipped: {2}。conflicts: {3}。"] =
            "requested: {0}. effective: {1}. skipped: {2}. conflicts: {3}.",

        // ---- capability matrix ---------------------------------------------
        ["选择 PE 后显示精确矩阵"] = "Choose a PE to see the precise matrix",
        ["marker VM/Ultra"] = "marker VM/Ultra",
        ["处理 SDK marker 区域与扫描函数"] = "Handles SDK marker regions and scanned functions",
        ["剥离目录并运行时重建 IAT"] = "Strips the directory and rebuilds the IAT at run time",
        ["许可/激活"] = "Licence / activation",
        ["x64 保护运行时校验"] = "Verified by the x64 protection runtime",
        ["DLL 禁止"] = "Not on a DLL",
        ["关闭 ASLR，需固定首选基址"] = "Disables ASLR; needs a fixed preferred base",
        ["会破坏 DLL 对外入口"] = "Would break the DLL's public entry points",
        ["EXE 可裁剪"] = "Safe to strip on an EXE",
        ["x64 loader 已验证"] = "x64 loader verified",
        ["x86 loader 已验证"] = "x86 loader verified",
        ["当前 VM 解释器仅 x64"] = "The current VM interpreter is x64 only",
        ["x86 loader 可重建 IAT"] = "The x86 loader can rebuild the IAT",
        ["保护运行时仅 x64"] = "The protection runtime is x64 only",
        ["ARM64"] = "ARM64",
        ["尚无 ARM64 loader；当前构建会被拒绝"] =
            "No ARM64 loader yet; this build would be refused",
        ["C#/VB .NET EXE"] = "C#/VB .NET EXE",
        ["采用 CLR 安全封装，不修改托管元数据和 IL"] =
            "Uses the CLR safe wrapper; managed metadata and IL are untouched",
        ["仅原生 x64 SDK marker"] = "Native x64 SDK markers only",
        ["导入/重定位/导出裁剪"] = "Import / relocation / export stripping",
        ["CLR 启动契约保持不变"] = "The CLR start-up contract stays intact",
        [".NET DLL"] = ".NET DLL",
        ["当前版本仅支持 EXE 输入"] = "This build accepts EXE input only",
        ["未知架构"] = "Unknown architecture",
        ["当前核心不支持"] = "Not supported by the current core",
        ["支持"] = "Supported",
        ["部分支持"] = "Partial",
        ["不支持"] = "Unsupported",
        ["冲突"] = "Conflict",

        // ---- protection core service ---------------------------------------
        ["找不到保护核心：{0}"] = "Protection core not found: {0}",
        ["对象规则 {0} 不是由 NovaProtect SDK marker 检测器生成"] =
            "Object rule {0} was not produced by the NovaProtect SDK marker detector",
        ["无法启动保护核心"] = "Could not start the protection core",
        ["操作已取消"] = "The operation was cancelled",
        ["无法启动检查工具"] = "Could not start the inspector",

        // ---- client/core handshake -----------------------------------------
        ["等待保护核心连接"] = "Waiting for the protection core to connect",
        ["保护核心拒绝调用：0x{0}。"] = "The protection core refused the call: 0x{0}.",
        ["验证保护核心进程"] = "Verifying the protection core process",
        ["读取授权挑战"] = "Reading the authorisation challenge",
        ["返回授权挑战"] = "Returning the authorisation challenge",
        ["退出码 0x{0}"] = "exit code 0x{0}",
        ["核心连接已关闭"] = "the core connection closed",
        ["保护核心在“{0}”阶段提前断开（{1}）。客户端组件可能不完整或签名已失效，请重新安装最新客户端。"] =
            "The protection core disconnected early during \"{0}\" ({1}). The client components may be incomplete or their signature may have expired; reinstall the latest client.",
        ["保护核心在“{0}”阶段连接中断（{1}）。客户端组件可能不完整或签名已失效，请重新安装最新客户端。"] =
            "The core connection dropped during \"{0}\" ({1}). The client components may be incomplete or their signature may have expired; reinstall the latest client.",

        // ---- function scanner ----------------------------------------------
        ["可虚拟化"] = "Virtualisable",
        ["含栈帧，VM 大概率跳过"] = "Has a stack frame; the VM will most likely skip it",
        ["函数过小，VM 跳过"] = "Function too small; the VM skips it",
        ["扫描到 {0} 个函数（{1}，共 {2} 个routine，跳过 {3} 个）"] =
            "Scanned {0} functions ({1}, {2} routines in total, {3} skipped)",
        ["文件太小，不是有效的 PE 映像"] = "The file is too small to be a valid PE image",
        ["缺少 MZ 文件头"] = "Missing the MZ header",
        ["PE 头偏移无效"] = "The PE header offset is invalid",
        ["缺少 PE 签名"] = "Missing the PE signature",
        ["不支持的机器类型 0x{0}（仅支持 x86 / x64）"] =
            "Unsupported machine type 0x{0} (x86 / x64 only)",
        ["ARM64 映像没有可枚举的 unwind 元数据，当前核心也不支持 ARM64 保护"] =
            "An ARM64 image has no enumerable unwind metadata, and the current core does not support ARM64 protection anyway",
        ["节表无效"] = "The section table is invalid",
        [".pdata 异常目录"] = "the .pdata exception directory",
        ["导出表 + 代码序言扫描"] = "export table + code prologue scan",
        ["代码序言扫描（无异常目录）"] = "code prologue scan (no exception directory)",

        // ---- PE inspector ---------------------------------------------------
        ["未知架构 0x{0}"] = "Unknown architecture 0x{0}",
        ["原生 DLL"] = "Native DLL",
        ["原生 EXE"] = "Native EXE",
        ["未知 PE 工具链"] = "Unknown PE toolchain",
        ["支持 x64 loader、导入虚拟化、SDK marker 区域 VM 与函数扫描 VM；函数面板可枚举并勾选任意函数。"] =
            "Supports the x64 loader, import virtualisation, SDK marker region VM and function-scan VM; the function panel can enumerate and tick any function.",
        ["支持 x86 loader、区段加密和导入虚拟化；VM/许可运行时仅支持 x64。"] =
            "Supports the x86 loader, section encryption and import virtualisation; the VM and licensing runtime are x64 only.",
        ["已识别 ARM64，但当前核心没有 ARM64 loader，构建会被拒绝。"] =
            "ARM64 recognised, but the current core has no ARM64 loader, so a build would be refused.",
        ["已识别 C#/VB .NET EXE；采用 CLR 安全封装保护，不重写托管元数据和 IL。"] =
            "C#/VB .NET EXE recognised; it is protected with the CLR safe wrapper, which rewrites neither managed metadata nor IL.",
        ["当前核心不支持此架构。"] = "The current core does not support this architecture.",
        ["读取失败"] = "Read failed",
        ["SDK 区域 {0}"] = "SDK region {0}",
        ["无效文件"] = "Invalid file",

        // ---- online update ---------------------------------------------------
        ["更新服务地址必须是 HTTPS，测试时允许回环地址。"] =
            "The update service URL must use HTTPS; a loopback address is allowed for testing.",
        ["GitHub 上还没有已发布的客户端版本。"] = "No client build has been published on GitHub yet.",
        ["当前版本暂时无法读取。"] = "The current version cannot be read right now.",
        ["GitHub 返回了无法识别的更新信息。"] = "GitHub returned update information this build cannot read.",
        ["GitHub 暂时无法连接。"] = "GitHub is unreachable right now.",
        ["GitHub 上还没有已发布的版本。"] = "Nothing has been published on GitHub yet.",
        ["暂时无法读取发布历史。"] = "The release history cannot be read right now.",
        ["GitHub 返回了无法识别的发布历史。"] = "GitHub returned a release history this build cannot read.",
        ["本次版本没有填写更新说明。"] = "This release carries no notes.",
        ["GitHub 上没有可显示的发布记录。"] = "GitHub has no release record to show.",
        ["更新文件地址不属于 GitHub 发布源。"] =
            "The update file URL does not belong to the GitHub release source.",
        ["更新文件暂时无法下载。"] = "The update file cannot be downloaded right now.",
        ["更新文件大小与发布信息不一致。"] =
            "The update file size does not match the published information.",
        ["更新文件超过声明大小。"] = "The update file exceeds its declared size.",
        ["更新文件下载不完整。"] = "The update download is incomplete.",
        ["更新文件 SHA-256 校验失败。"] = "The update file failed its SHA-256 check.",
        ["更新下载已取消。"] = "The update download was cancelled.",
        ["CDNfly 边缘防护拦截了请求（444）。请对 /api/ 和 /download 配置最高优先级放行并关闭 JS/CC 验证。"] =
            "CDNfly edge protection blocked the request (444). Give /api/ and /download top-priority allow rules and turn off JS/CC verification.",
        ["CDNfly 返回了人机验证页面，更新接口尚未放行。请对 /api/ 配置旁路验证。"] =
            "CDNfly returned a human-verification page; the update endpoint is not yet allowed through. Exempt /api/ from verification.",
        ["该版本尚未发布。"] = "That version has not been published.",
        ["更新信息字段不完整。"] = "The update information is missing fields.",
        ["发布标签不是三段式版本号。"] = "The release tag is not a three-part version number.",
        ["更新信息格式无效。"] = "The update information format is invalid.",
        ["该版本没有附带安装包。"] = "That release has no installer attached.",
        ["该版本未提供 SHA-256 摘要，无法校验安装包。"] =
            "That release provides no SHA-256 digest, so the installer cannot be verified.",
        ["安装包大小无效。"] = "The installer size is invalid.",
        ["更新下载地址不属于 GitHub 发布源。"] =
            "The update download URL does not belong to the GitHub release source.",
        ["当前版本号无效。"] = "The current version number is invalid.",
        ["更新信息校验失败。"] = "The update information failed validation.",
        ["更新版本策略无效。"] = "The update version policy is invalid.",

        // ---- log trimming / core invocation / PE inspector ---------------
        ["，仅保留最近内容 …\n"] = ", keeping only the most recent output …\n",
        ["保护核心拒绝调用：0x{0:X8}。"] = "The protection core refused the call: 0x{0:X8}.",
        ["退出码 0x{0:X8}"] = "exit code 0x{0:X8}",
        ["未知架构 0x{0:X4}"] = "Unknown architecture 0x{0:X4}",
        ["不支持的机器类型 0x{0:X4}（仅支持 x86 / x64）"] =
            "Unsupported machine type 0x{0:X4} (only x86 / x64 are supported)",

        // ---- protection plan capability names ----------------------------
        ["区段打包"] = "Section packing",
        ["反沙箱检测"] = "Anti-sandbox checks",
        ["重定位裁剪并关闭 ASLR"] = "Relocation stripping with ASLR off",
        ["CPUID 退出成本探测"] = "CPUID exit-cost probe",

    };
}
