<?php
declare(strict_types=1);

/**
 * English translations for the marketing site.
 *
 * Keyed by the Chinese source text, so a lookup can only miss when a page
 * gained a string this file has not seen yet — and the miss renders as correct
 * Chinese rather than an empty label. Keys must match the source byte for byte,
 * full-width punctuation included.
 *
 * Markup inside a key is part of the key: the translated value has to carry the
 * same tags so the page keeps its emphasis and links.
 *
 * @return array<string, string>
 */
return [

    // ---- shell (lib/layout.php) ------------------------------------------
    '跳转到主要内容' => 'Skip to main content',
    '主导航' => 'Primary',
    '打开菜单' => 'Open menu',
    '关闭菜单' => 'Close menu',
    '最新客户端版本' => 'Latest client version',
    '视觉主题' => 'Visual theme',
    '液态玻璃' => 'Liquid glass',
    '新波普' => 'Neo pop',
    '暗色实验室' => 'Dark lab',
    '玻璃' => 'Glass',
    '波普' => 'Pop',
    '实验室' => 'Lab',
    '界面语言' => 'Interface language',
    '中文' => 'Chinese',
    '英文' => 'English',
    '功能' => 'Features',
    '下载' => 'Download',
    '下载客户端' => 'Download client',
    '更新日志' => 'Changelog',
    '隐私' => 'Privacy',
    'SDK 文档' => 'SDK docs',
    '面向 Windows EXE 的代码保护工作台' => 'A code protection workbench for Windows EXEs',
    '客户端版本与更新说明每五分钟自动同步自 <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub Releases</a>。'
        => 'Client versions and release notes sync from <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub Releases</a> every five minutes.',

    // ---- home (public/index.php) ------------------------------------------
    '代码保护工具' => 'Code protection tool',
    'NovaProtect 是面向 Windows EXE 的代码保护工作台，支持 C/C++、C#/VB .NET、Rust、Golang，提供保护模式、运行时防护、函数级虚拟化与 SDK 标记。'
        => 'NovaProtect is a code protection workbench for Windows EXEs. It supports C/C++, C#/VB .NET, Rust and Golang, and provides protection modes, runtime guards, function-level virtualization and SDK markers.',
    '让关键代码<br><span class="grad-text">更难被读懂</span>'
        => 'Make critical code<br><span class="grad-text">much harder to read</span>',
    'NovaProtect —— 面向 Windows EXE 的代码保护工作台。'
        => 'NovaProtect — a code protection workbench for Windows EXEs.',
    '支持 C/C++、C#/VB .NET、Rust 与 Golang EXE。用 SDK 标记或函数扫描（.pdata 枚举）圈定要保护的函数与区域，构建前即可看到实际生效的保护项。翻译器覆盖绝大多数编译器产出的 x86-64 代码——同一目标 5266 个函数实测 <strong>100.0% 的函数字节被虚拟化</strong>（chunk 全部可虚拟化、零拒绝桶）。'
        => 'Works on C/C++, C#/VB .NET, Rust and Golang EXEs. Mark the functions and regions to protect with SDK markers or the function scanner (.pdata enumeration), and see which protections actually take effect before you build. The translator covers x86-64 code from virtually every compiler: across 5266 functions in one measured target, <strong>100.0% of function bytes were virtualized</strong> (every chunk virtualizable, zero reject buckets).',
    '全部功能' => 'All features',
    '客户端' => 'Client',
    '每五分钟自动同步 GitHub 版本' => 'GitHub versions synced every five minutes',
    '版本信息暂时不可用' => 'Version information is unavailable right now',
    '虚拟化' => 'Virtualization',
    '反调试' => 'Anti-debug',
    '区段加密' => 'Section encryption',
    '硬件绑定' => 'Hardware binding',
    '4 种工具链' => '4 toolchains',
    '原生保护 · .NET 封装' => 'Native protection · .NET wrapping',
    '无需账户' => 'No account needed',
    '下载与更新全部走 GitHub' => 'Downloads and updates go through GitHub',
    '构建前可见' => 'Visible before building',
    '请求项 · 生效项 · 跳过项' => 'Requested · applied · skipped',
    '客户端的全部能力' => 'Everything the client does',
    '从目标分析、策略配置到构建输出的一体化工作台。每项能力都可在<a href="/features/">功能详解</a>中查看参数与约束。'
        => 'One workbench from target analysis and policy setup through to build output. Every capability is documented with its parameters and limits in the <a href="/features/">feature reference</a>.',
    '了解详情 →' => 'Learn more →',
    '五步完成一次保护构建' => 'A protection build in five steps',
    '保护对象明确、配置效果透明、过程可追溯——这是 NovaProtect 的三条设计原则。'
        => 'An explicit protection target, a transparent configuration, and a traceable process — the three design principles behind NovaProtect.',
    '产品构成' => 'What it is made of',
    '界面、引擎、运行时与 SDK 协同工作，围绕商业软件中的核心算法与关键业务逻辑提供可配置的保护流程。'
        => 'The interface, engine, runtime and SDK work together, providing a configurable protection pipeline around the core algorithms and business logic in commercial software.',
    '开始使用' => 'Get started',
    '下载 NovaProtect 客户端' => 'Download the NovaProtect client',
    'Windows x64 安装包发布在 GitHub Releases，无需账户。安装包附 SHA-256 摘要，更新器下载后逐字节校验。'
        => 'Windows x64 installers are published on GitHub Releases with no account required. Each installer ships with a SHA-256 digest that the updater verifies byte for byte after downloading.',
    '下载最新版' => 'Download latest',
    '在 GitHub 查看' => 'View on GitHub',

    // home — feature cards
    '三种保护模式' => 'Three protection modes',
    '变异、虚拟化与 Ultra 管线，配合兼容 / 均衡 / 高强度 / Ultra 四档预设，强度参数仍可逐项微调。'
        => 'Mutation, virtualization and the Ultra pipeline, with Compatible / Balanced / High / Ultra presets and every strength parameter still tunable one by one.',
    '运行时防护' => 'Runtime guards',
    '反调试、环境检查、反沙箱、反内存转储、交互桌面自检、进程自隔离与延时复测，级别可调。'
        => 'Anti-debug, environment checks, anti-sandbox, anti-dump, interactive-desktop self-check, process self-isolation and delayed re-checks, each with adjustable levels.',
    '函数级虚拟化' => 'Function-level virtualization',
    'VMP 式函数扫描器一键枚举 x64 函数表，或用 SDK 标记关键区域，逐个勾选进入 VM 保护。'
        => 'A VMProtect-style function scanner enumerates the x64 function table in one click, or mark critical regions with the SDK and tick each one into VM protection.',
    '对抗与规避' => 'Countermeasures and evasion',
    '关闭 / 均衡 / 激进 / 偏执四档策略，构建签名种子可复现，内核与 hypervisor 探针、环境闸门可审计。'
        => 'Off / Balanced / Aggressive / Paranoid strategies, a reproducible build-signature seed, and auditable kernel and hypervisor probes plus an environment gate.',
    '输出处理与许可' => 'Output handling and licensing',
    '区段压缩与加密、调试与重定位裁剪；水印、许可密钥、一机一码硬件绑定与虚拟文件容器。'
        => 'Section compression and encryption, debug and relocation trimming; watermarks, licence keys, one-machine-one-code hardware binding and a virtual file container.',
    '检查工具' => 'Inspector',
    '只读检查 PE 信息、嵌入水印、虚拟文件清单与本机激活 ID，不修改任何目标文件。'
        => 'Read-only inspection of PE information, embedded watermarks, the virtual file list and the local activation ID — no target file is ever modified.',
    '构建可观测' => 'Observable builds',
    '目标能力矩阵展示请求项与实际生效项，实时进度与日志输出，项目文件可保存、导入与导出。'
        => 'A per-target capability matrix shows what was requested against what actually applies, alongside live progress and logs; project files save, import and export.',
    '在线更新' => 'Online update',
    '客户端直接从 GitHub Releases 检查更新并按摘要校验安装包；运行记录保存在本机。'
        => 'The client checks GitHub Releases directly and verifies the installer against its digest; run history stays on the local machine.',

    // home — workflow steps
    '导入目标' => 'Import the target',
    '拖放或选择 C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE，客户端立即解析 PE 结构与 SDK 标记。'
        => 'Drop in or pick an x86/x64 EXE built with C/C++, C#/VB .NET, Rust or Golang; the client immediately parses the PE structure and SDK markers.',
    '配置策略' => 'Set the strategy',
    '选择保护模式与预设，微调变异强度与 VM 复杂度，按需开启运行时防护、输出处理与许可绑定。'
        => 'Choose a protection mode and preset, tune mutation strength and VM complexity, and switch on runtime guards, output handling and licence binding as needed.',
    '查看生效能力' => 'Review what applies',
    '构建前展示当前目标的能力矩阵：哪些请求会生效、哪些被安全跳过、冲突原因是什么。'
        => 'Before the build, the capability matrix shows which requests apply, which are skipped for safety, and why anything conflicts.',
    '开始保护' => 'Start protection',
    '后台生成受保护版本，实时进度与日志全程可见；中断与取消随时可用。'
        => 'The protected build is produced in the background with live progress and logs throughout; pause and cancel are always available.',
    '校验输出' => 'Verify the output',
    '用检查工具读取水印与虚拟文件清单，比对 SHA-256，确认输出与配置一致后发布。'
        => 'Use the inspector to read the watermark and virtual file list, compare the SHA-256, and ship only once the output matches the configuration.',

    // home — modules
    '可视化客户端' => 'Visual client',
    'C# + WinUI 3 工作台：项目配置、区域编辑、深浅色主题、构建进度与日志。'
        => 'A C# + WinUI 3 workbench: project configuration, region editing, light and dark themes, build progress and logs.',
    '原生保护引擎' => 'Native protection engine',
    'C++ 实现 PE 分析、区段打包、导入处理、虚拟指令转换与输出构建。'
        => 'C++ implements PE analysis, section packing, import handling, virtual instruction translation and output construction.',
    '保护运行时' => 'Protection runtime',
    'x86/x64 加载器、x64 虚拟指令解释器与 .NET 专用启动宿主，随目标程序运行。'
        => 'The x86/x64 loader, the x64 virtual instruction interpreter and a dedicated .NET launch host, all running alongside the target program.',
    'SDK 与项目管理' => 'SDK and project management',
    '源码标记关键区域，项目文件与构建快照让配置可复用、可核查、可追溯。'
        => 'Mark critical regions in source; project files and build snapshots keep configurations reusable, checkable and traceable.',
    '<strong>保护原理：</strong>区段打包与 XOR 加密、SDK 标记/函数扫描选中的区域虚拟化为内部虚拟指令（栈帧函数的序言与尾声同样进 VM，多返回与尾调用正确）、VM 字节码全程密文 + 执行期按需解码、Ultra 前置变异与指令混淆、可选 4 层再虚拟化、导入表运行时重建、载荷完整性校验，以及基于 XTEA 的 .NET 加密封装。'
        => '<strong>How it protects:</strong> section packing with XOR encryption; SDK-marked or scanner-selected regions lowered to internal virtual instructions (a stack-frame function keeps its prologue and epilogue in the VM too, and multiple returns and tail calls stay correct); VM bytecode encrypted throughout and decoded on demand at execution; Ultra pre-mutation and instruction obfuscation; optional four-level re-virtualization; runtime import table rebuilding; payload integrity checks; and XTEA-based encrypted .NET wrapping.',

    // ---- 404 -------------------------------------------------------------
    '页面不存在' => 'Page not found',
    '这个地址没有对应的内容。可以从首页重新开始。' => 'Nothing lives at this address. Start again from the home page.',
    '返回首页' => 'Back to home',
    '页面不存在。' => 'Page not found.',

    // ---- download --------------------------------------------------------
    '下载 NovaProtect' => 'Download NovaProtect',
    'Windows x64 客户端，无需账户即可下载。安装包发布在 GitHub Releases，本站不托管二进制文件；版本信息每五分钟自动同步一次。'
        => 'The Windows x64 client, downloadable without an account. Installers are published on GitHub Releases — this site hosts no binaries — and version information syncs every five minutes.',
    '预发布' => 'Pre-release',
    '正式版' => 'Stable',
    '发布' => 'published',
    '下载安装包' => 'Download installer',
    '<strong>本次更新：</strong>' => '<strong>What changed:</strong>',
    '完整性与签名' => 'Integrity and signing',
    '每个版本的 SHA-256 摘要随 Release 附件发布，上方校验值取自 GitHub 提供的素材摘要。客户端更新器下载后逐字节校验，不一致就不会安装。'
        => 'Every release publishes its SHA-256 digest as an asset, and the value above is taken from the digest GitHub reports. The client updater verifies byte for byte after downloading and refuses to install on a mismatch.',
    '安装包未附带 Authenticode 签名，Windows 可能提示未知发布者；请以哈希核对结果为准。'
        => 'The installer carries no Authenticode signature, so Windows may warn about an unknown publisher; treat the hash comparison as the source of truth.',
    '客户端如何更新' => 'How the client updates',
    '桌面客户端直接向 GitHub 检查更新并下载安装包，不经过本站。本站只是说明页面——没有后台、没有数据库。'
        => 'The desktop client checks GitHub directly and downloads installers there, never through this site. This site is documentation only — no backend, no database.',
    '近期版本' => 'Recent releases',
    '完整列表见<a href="/client-updates/">更新日志</a>。' => 'See the <a href="/client-updates/">changelog</a> for the full list.',
    '下载 / 查看' => 'Download / view',
    '无法读取 GitHub Releases。请稍后刷新，或直接访问 %s 页面。'
        => 'Could not read GitHub Releases. Refresh in a moment, or open the %s page.',
    '系统要求' => 'Requirements',
    'Windows 10 / 11 x64（安装包目标平台）' => 'Windows 10 / 11 x64 (the installer platform target)',
    '被保护目标：C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE'
        => 'Protected targets: x86/x64 EXEs built with C/C++, C#/VB .NET, Rust or Golang',
    '无需账户、无需联网即可使用保护功能；仅在线更新需要访问 GitHub'
        => 'Protection works without an account or a network connection; only the online update needs GitHub',
    '下载 NovaProtect Windows x64 客户端。安装包发布在 GitHub Releases，附 SHA-256 摘要，每五分钟自动同步 GitHub 版本。'
        => 'Download the NovaProtect Windows x64 client. Installers are published on GitHub Releases with SHA-256 digests; GitHub versions sync every five minutes.',

    // ---- client updates --------------------------------------------------
    '客户端更新日志' => 'Client changelog',
    'NovaProtect 客户端更新日志，每五分钟自动同步 GitHub Releases 版本与说明。'
        => 'The NovaProtect client changelog, syncing versions and release notes from GitHub Releases every five minutes.',
    '客户端版本与更新说明直接取自 GitHub Releases，每五分钟自动同步一次——页面上出现的每个版本都是真实发布。'
        => 'Client versions and release notes come straight from GitHub Releases and sync every five minutes — every version on this page is a real publication.',
    '数据来源：<a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">sudfiona/NovaProtect Releases</a>'
        => 'Source: <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">sudfiona/NovaProtect Releases</a>',
    '暂无更新记录' => 'No releases yet',
    '暂时无法读取 GitHub Releases，请稍后刷新或直接访问 <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub</a>。'
        => 'GitHub Releases cannot be read right now. Refresh in a moment, or open <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub</a> directly.',
    '下载此版本' => 'Download this release',
    '在 GitHub 查看 →' => 'View on GitHub →',

    // ---- privacy ---------------------------------------------------------
    '隐私说明' => 'Privacy notice',
    'NovaProtect 官网隐私说明：无账户、不收集访问数据；界面语言 Cookie 只记录语言选择，客户端更新直连 GitHub。'
        => 'NovaProtect privacy notice: no accounts and no visitor data collected; the interface-language cookie only remembers your choice, and client updates go straight to GitHub.',
    'NovaProtect 是纯静态说明页面，不收集访问数据、不做用户追踪；只有你主动切换界面语言时，才会写入一个记录语言选择的 Cookie。'
        => 'NovaProtect is a static documentation site. It collects no visitor data and does not track users; the only cookie is written when you actively switch the interface language, to remember that choice.',
    ' NovaProtect <strong>不提供</strong>用户账户、会员或邮件验证服务。本站没有后台、没有数据库，也不需要登录。'
        => ' NovaProtect <strong>offers no</strong> user accounts, memberships or email verification. This site has no backend, no database, and requires no login.',
    '客户端下载指向 GitHub Releases，下载行为受 <a href="https://docs.github.com/site/github/getting-started-with-github/privacy-policies" target="_blank" rel="noopener noreferrer">GitHub 的隐私政策</a> 约束。'
        => 'Client downloads point at GitHub Releases, so the download itself is governed by <a href="https://docs.github.com/site/github/getting-started-with-github/privacy-policies" target="_blank" rel="noopener noreferrer">GitHub\'s privacy policy</a>.',
    '桌面客户端通过 HTTPS 直接连 GitHub 检查更新并下载安装包，<strong>不经过本站</strong>；更新时按 GitHub 提供的摘要逐字节校验安装包。'
        => 'The desktop client connects to GitHub over HTTPS to check for updates and download installers, <strong>never through this site</strong>, and verifies each installer byte for byte against the digest GitHub publishes.',
    '客户端在本机保存运行记录、规避设置与诊断日志（可在设置页打开对应目录），这些数据<strong>不会上传</strong>到任何服务器，也与本站无关。'
        => 'The client stores run history, evasion settings and diagnostic logs on the local machine (the Settings page opens those folders); this data is <strong>never uploaded</strong> anywhere and has nothing to do with this site.',
    '界面语言 Cookie（<code class="inline">np-lang</code>）只保存 <code class="inline">zh</code> 或 <code class="inline">en</code> 两个值之一，用于记住你的语言选择，不含标识符、不含追踪信息，有效期一年，清除浏览器 Cookie 即可删除。'
        => 'The interface-language cookie (<code class="inline">np-lang</code>) holds exactly one of <code class="inline">zh</code> or <code class="inline">en</code> to remember your choice. It contains no identifier and no tracking data, lasts one year, and disappears when you clear browser cookies.',
    '本站服务端仅在页面渲染时读取 GitHub Releases 公开数据并做短时缓存（默认每五分钟同步一次），不记录访问者身份。'
        => 'The server only reads public GitHub Releases data while rendering a page and keeps it in a short-lived cache (syncing every five minutes by default). It records no visitor identity.',

    // ---- features --------------------------------------------------------
    '功能详解' => 'Feature reference',
    'NovaProtect 客户端功能详解：保护模式、运行时防护、输出处理、函数与区域保护、对抗与规避、检查工具与在线更新的完整参数说明。'
        => 'The NovaProtect feature reference: complete parameter documentation for protection modes, runtime guards, output handling, function and region protection, evasion, the inspector and online updates.',
    '客户端功能详解' => 'Every client feature',
    'NovaProtect 客户端的全部页面、参数与约束。所有数值范围与默认值以客户端界面为准，构建前请以「当前目标能力」中的实际生效结果为最终依据。'
        => 'Every page, parameter and constraint in the NovaProtect client. Ranges and defaults follow the client interface, and the authoritative answer before a build is whatever the capability matrix reports for the current target.',
    '本页目录' => 'On this page',
    '客户端总览' => 'Client overview',
    'WinUI 3 桌面工作台，左侧导航包含六个入口；设置页提供外观、界面语言、数据与诊断、在线更新。'
        => 'A WinUI 3 desktop workbench with six entries in the left navigation; the Settings page covers appearance, interface language, data and diagnostics, and online update.',
    '页面' => 'Page',
    '作用' => 'Purpose',
    '保护项目' => 'Protect project',
    '选择目标、配置保护策略、查看能力矩阵、执行构建并观察实时日志。'
        => 'Pick the target, configure the protection strategy, review the capability matrix, run the build and watch the live log.',
    '静态特征清洗、动态探测强度、内核与 hypervisor 探针、环境闸门阈值。'
        => 'Static signature scrubbing, dynamic probe strength, kernel and hypervisor probes, and environment gate thresholds.',
    '只读检查 PE 信息、水印、虚拟文件清单与本机激活 ID。'
        => 'Read-only inspection of PE information, watermarks, the virtual file list and the local activation ID.',
    '运行记录' => 'Activity',
    '本机保存的历次运行摘要，可单条删除或清空。' => 'A local summary of past runs, deletable one at a time or all at once.',
    '与 GitHub Releases 同步的客户端版本说明，每五分钟自动刷新。'
        => 'Client release notes synced from GitHub Releases and refreshed every five minutes.',
    '设置' => 'Settings',
    '外观主题、界面语言、数据与诊断目录、在线更新检查与安装。'
        => 'Appearance theme, interface language, data and diagnostics folders, and online update checks and installs.',
    '客户端<b>不需要账户登录</b>；官网仅提供说明与下载入口，安装包与版本元数据全部来自 GitHub Releases。'
        => 'The client <b>requires no account</b>; this site only provides documentation and a download entry point, with installers and version metadata all coming from GitHub Releases.',
    '选择应用、调整保护策略，然后在后台生成受保护版本。'
        => 'Choose an application, adjust the protection strategy, and generate the protected build in the background.',
    '目标文件' => 'Target file',
    '支持 <strong>C/C++、C#/VB .NET、Rust、Golang</strong> 生成的 x86/x64 EXE；支持拖放到文件卡片。'
        => 'Supports x86/x64 EXEs built with <strong>C/C++, C#/VB .NET, Rust and Golang</strong>; files can be dropped onto the file card.',
    '输入文件选择后自动解析 PE 结构、架构与 SDK 标记；输出文件默认生成 <code class="inline">*_protected.exe</code>，可另存为任意路径。'
        => 'Choosing an input file immediately parses its PE structure, architecture and SDK markers; the output defaults to <code class="inline">*_protected.exe</code> and can be saved anywhere.',
    '顶部命令栏支持<b>导入项目</b>、<b>保存项目</b>、<b>导出项目</b>与<b>导出当前构建计划</b>——配置可复用、可核查、可追溯。'
        => 'The top command bar supports <b>import project</b>, <b>save project</b>, <b>export project</b> and <b>export the current build plan</b> — configurations stay reusable, checkable and traceable.',
    '保护模式与预设' => 'Protection modes and presets',
    '模式决定代码处理管线；强度参数仍可单独微调。'
        => 'The mode selects the code pipeline; the strength parameters remain individually tunable.',
    '模式' => 'Mode',
    '说明' => 'Notes',
    '变异模式' => 'Mutation mode',
    '对适用代码执行 VM 前置指令变异与混淆，不进入虚拟化管线。'
        => 'Applies pre-VM instruction mutation and obfuscation to eligible code without entering the virtualization pipeline.',
    '虚拟化模式' => 'Virtualization mode',
    '把可翻译的 SDK 区域 / 函数降级为内部虚拟指令，由 x64 解释器执行。'
        => 'Lowers translatable SDK regions and functions to internal virtual instructions executed by the x64 interpreter.',
    'Ultra 模式' => 'Ultra mode',
    '同时启用代码变异与虚拟化，适合需要最高保护等级的 x64 程序。'
        => 'Enables mutation and virtualization together, for x64 programs that need the highest protection level.',
    '参数' => 'Parameter',
    '范围' => 'Range',
    '预设' => 'Preset',
    '兼容 / 均衡 / 高强度 / Ultra' => 'Compatible / Balanced / High / Ultra',
    '预设只调整已实现能力；构建前会显示请求值与实际生效值。'
        => 'A preset only adjusts implemented capabilities; the requested and effective values are both shown before a build.',
    '变异强度' => 'Mutation strength',
    '垃圾指令与变异密度的全局档位（低 / 中等 / 高强度…按界面标签显示）。'
        => 'The global level for junk instructions and mutation density (low / medium / high… labelled by the interface).',
    'VM 复杂度' => 'VM complexity',
    '虚拟指令集与解释路径的复杂度，越高越难静态还原，运行开销也越大。'
        => 'The complexity of the virtual instruction set and interpretation path. Higher is harder to reverse statically and costs more at runtime.',
    '二次虚拟化' => 'Re-virtualization',
    '开 / 关' => 'On / off',
    '阶段拆分 + 二级解释器 + 寄存器重映射；<b>仅 x64 生效</b>。'
        => 'Stage splitting plus a second-level interpreter and register remapping; <b>x64 only</b>.',
    '嵌套层级' => 'Nesting depth',
    '二次虚拟化的嵌套深度。' => 'How deeply re-virtualization nests.',
    '运行时防护' => 'Runtime guards',
    '打包时注入目标运行时的防护开关；只对受支持的架构生效，按需开启避免误杀。'
        => 'Guard switches injected into the target runtime at pack time. They only apply to supported architectures; enable them deliberately to avoid false positives.',
    '项' => 'Item',
    '取值 / 说明' => 'Value / notes',
    '反调试级别' => 'Anti-debug level',
    '关闭 / 基础 / 增强 / 严格' => 'Off / Basic / Enhanced / Strict',
    '环境检查级别' => 'Environment check level',
    '关闭 / 基础 / 增强' => 'Off / Basic / Enhanced',
    '内存完整性保护' => 'Memory integrity protection',
    '按目标架构与配置执行载荷或代码区域完整性校验'
        => 'Verifies payload or code-region integrity according to the target architecture and configuration',
    '导入表保护' => 'Import table protection',
    '保存导入信息、运行时重建导入地址表，改变常规静态导入结构'
        => 'Saves import information and rebuilds the import address table at runtime, changing the usual static import structure',
    '资源区段保护' => 'Resource section protection',
    '加密资源区段时保留程序图标，资源管理器中显示与原文件一致'
        => 'Keeps the program icon while encrypting the resource section, so Explorer shows the same icon as the original file',
    '沙箱环境检测' => 'Sandbox detection',
    '累计评分 CPU 数、内存、沙箱模块、时序等信号，超阈值拒绝执行'
        => 'Scores CPU count, memory, sandbox modules and timing signals cumulatively, and refuses to run past the threshold',
    '反内存转储' => 'Anti-dump',
    '校验 MZ/PE 头、区段表与 PEB 加载基址，拦截 Procdump/Minidump 后处理'
        => 'Verifies the MZ/PE headers, section table and PEB load base, blocking Procdump/Minidump post-processing',
    '交互桌面环境自检' => 'Interactive desktop self-check',
    '校验 CPU 数、内存、开机时长、屏幕分辨率、显示器数'
        => 'Verifies CPU count, memory, uptime, screen resolution and monitor count',
    '进程自隔离' => 'Process self-isolation',
    '拒绝外部读取进程内存' => 'Refuses external reads of process memory',
    '延时复测抽查' => 'Delayed re-check',
    '随沙箱检测自动开启；延迟后二次校验环境信号'
        => 'Turns on with sandbox detection; re-checks environment signals after a delay',
    '输出处理' => 'Output handling',
    '区段压缩' => 'Section compression',
    '对符合条件的原生代码区段打包，按压缩收益决定是否压缩'
        => 'Packs eligible native code sections, compressing only when it pays off',
    '区段加密' => 'Section encryption',
    '启用时对打包区段采用 XOR 编码，启动后由对应架构加载器恢复'
        => 'When enabled, packs sections with XOR encoding and restores them at startup through the matching loader',
    '移除调试目录' => 'Strip debug directory',
    '输出中不再保留调试信息目录' => 'Drops the debug information directory from the output',
    '裁剪重定位并关闭 ASLR' => 'Trim relocations and disable ASLR',
    '仅原生 EXE；改变常规重定位布局' => 'Native EXE only; changes the usual relocation layout',
    '裁剪导出目录' => 'Strip export directory',
    '仅原生 EXE；移除导出表' => 'Native EXE only; removes the export table',
    '.NET EXE 采用 CLR 安全封装，会跳过破坏 CLR 契约的选项；导入虚拟化在运行时通过 IAT 重建完成。'
        => '.NET EXEs use CLR-safe wrapping and skip any option that would break the CLR contract; import virtualization is completed at runtime by rebuilding the IAT.',
    '许可、标识与虚拟文件' => 'Licensing, marking and virtual files',
    '<strong>水印</strong>：可选的产品或构建标识，写入元数据，可用检查工具读取。'
        => '<strong>Watermark</strong>: an optional product or build marker written into metadata and readable with the inspector.',
    '<strong>许可密钥</strong>：可选；许可数据由 x64 保护运行时执行校验。'
        => '<strong>Licence key</strong>: optional; the licence data is verified by the x64 protection runtime.',
    '<strong>激活 / 硬件绑定（一机一码）</strong>：填 16 位机器 ID，或 <code class="inline">auto</code> 绑定构建机；本机激活 ID 可在检查工具中读取。'
        => '<strong>Activation / hardware binding (one machine, one code)</strong>: enter a 16-character machine ID, or use <code class="inline">auto</code> to bind the build machine; the local activation ID is readable in the inspector.',
    '<strong>虚拟文件</strong>：向虚拟文件容器添加任意文件，随受保护文件输出；可列表管理与移除。'
        => '<strong>Virtual files</strong>: add any file to the virtual file container and it ships with the protected file; list and remove them as needed.',
    '内部核心不支持直接命令调用；许可与激活绑定的能力边界以运行时实际行为为准。'
        => 'The internal core does not support direct command invocation; the real limits of licensing and activation binding are whatever the runtime actually does.',
    '函数与区域保护' => 'Function and region protection',
    '<strong>SDK 标记（区域对象编辑器）</strong>：SDK marker 区域直接来自目标文件中的 NovaProtect BEGIN/END 字节模式。每个区域可设置：'
        => '<strong>SDK markers (region object editor)</strong>: SDK marker regions come straight from the NovaProtect BEGIN/END byte patterns in the target file. Each region can set:',
    '显示名称；对象模式（继承全局 / 跳过此区域 / 虚拟化 / Ultra）；'
        => 'a display name; the object mode (inherit global / skip this region / virtualize / Ultra);',
    'VM 复杂度 0–10、变异强度 0–3；' => 'VM complexity 0–10 and mutation strength 0–3;',
    '「此区域要求启用全局激活绑定」开关；右侧显示区域 RVA 范围。'
        => 'a “this region requires global activation binding” switch, with the region RVA range shown on the right.',
    '<strong>函数保护（VMP 式扫描）</strong>：扫描目标文件的函数表，勾选加入 VM 保护，无需改源码。'
        => '<strong>Function protection (VMProtect-style scan)</strong>: scan the target function table and tick functions into VM protection without touching source code.',
    'x64 读取 <code class="inline">.pdata</code> 异常目录枚举运行时函数（含静态函数），按 RVA 排序；'
        => 'On x64 it reads the <code class="inline">.pdata</code> exception directory to enumerate runtime functions (static ones included), sorted by RVA;',
    '列表列：名称 / 地址范围 / 所在节 / 大小 / 模式 / 可虚拟化性；'
        => 'Columns: name / address range / section / size / mode / virtualizability;',
    '过滤：全部函数 / 仅可虚拟化 / 仅导出函数 / 仅已勾选；'
        => 'Filters: all functions / virtualizable only / exported only / ticked only;',
    '批量：全选、反选、<b>添加所有函数</b>（勾选全部可虚拟化函数）、清除勾选；'
        => 'Bulk actions: select all, invert, <b>add all functions</b> (tick every virtualizable function), clear selection;',
    '批量应用：继承全局模式 / 虚拟化 / Ultra / 仅前置变异 / 跳过，附 VM 复杂度、变异强度与激活锁定。'
        => 'Bulk apply: inherit global / virtualize / Ultra / pre-mutation only / skip, together with VM complexity, mutation strength and the activation lock.',
    '<strong>约束：</strong>区域表上限 8192（2.3.20 起放开）；函数级虚拟化覆盖整段函数体——多返回、共享尾声、尾调用与栈帧访问都正确（帧序言与尾声同样进 VM）；降不了的形式经原生桥执行，函数其余部分照常虚拟化。详见 <a href="/sdk/">SDK 文档</a>。'
        => '<strong>Constraints:</strong> the region table holds up to 8192 entries (raised in 2.3.20); function-level virtualization covers the whole function body — multiple returns, shared epilogues, tail calls and stack-frame access all stay correct, with the frame prologue and epilogue in the VM too; forms that cannot be lowered run through a native bridge while the rest of the function stays virtualized. See the <a href="/sdk/">SDK docs</a>.',
    '构建执行与日志' => 'Build execution and logs',
    '<strong>当前目标能力</strong>：构建前逐项展示请求值、生效值、跳过项与冲突原因——状态来自实际核心能力与 PE 类型。'
        => '<strong>Current target capability</strong>: before a build it lists the requested value, the effective value, anything skipped and the reason for each conflict, all derived from the real core capability and the PE type.',
    '<strong>开始保护</strong>：状态行 + 进度条 + 配置摘要；构建中可取消，完成后输出路径可直接打开。'
        => '<strong>Start protection</strong>: a status line, progress bar and configuration summary; the build can be cancelled, and the output path opens directly once it finishes.',
    '<strong>实时日志</strong>：完整构建过程输出，可一键清空；日志同时写入本机诊断目录。'
        => '<strong>Live log</strong>: the complete build output, clearable in one click and also written to the local diagnostics folder.',
    '控制静态特征清洗、反分析探测与内核驱动探针。这些设置对保护项目页的每次运行生效。'
        => 'Controls static signature scrubbing, anti-analysis probes and kernel driver probes. These settings apply to every run from the Protect project page.',
    '规避档位' => 'Evasion level',
    '档位' => 'Level',
    '取向' => 'Approach',
    '关闭' => 'Off',
    '不做静态特征清洗与动态探测' => 'No static signature scrubbing and no dynamic probes',
    '均衡' => 'Balanced',
    '默认。清洗静态特征，加入反沙箱评分、垃圾指令与内存流式解密，误报率与强度平衡'
        => 'The default. Scrubs static signatures and adds sandbox scoring, junk instructions and streaming memory decryption, balancing false positives against strength',
    '激进' => 'Aggressive',
    '更高探测强度与特征变换，适合对抗意愿明确的分发场景'
        => 'Stronger probes and heavier signature transformation, for distribution where resistance is expected',
    '偏执' => 'Paranoid',
    '最强清洗与探测组合，真实环境误触发概率也最高'
        => 'The strongest scrubbing and probe combination, and the most likely to misfire on real machines',
    '档位展开明细以表格形式列出四个档位在十余个字段上的差异；具体数值请在客户端内展开查看。'
        => 'Expanding a level shows a table of how the four levels differ across a dozen or so fields; see the client for the specific values.',
    '构建签名种子' => 'Build signature seed',
    '种子决定标签、nonce、节区后缀、填充与探测顺序；<strong>留空 = 每次从系统熵取新值</strong>，两次构建不共享字节特征。'
        => 'The seed determines tags, nonces, section suffixes, padding and probe order; <strong>leaving it empty draws fresh system entropy every time</strong>, so two builds share no byte signatures.',
    '填入 1–16 位十六进制可复现同一构建；提供「生成」随机种子与「复制」按钮。'
        => 'Entering 1–16 hex digits reproduces the same build; there are random-seed “generate” and “copy” buttons.',
    '「每次构建重新随机」开关：已开启时忽略种子、重新取熵。'
        => 'The “re-randomize every build” switch ignores the seed and draws new entropy when enabled.',
    '动态对抗' => 'Dynamic countermeasures',
    '范围 / 默认' => 'Range / default',
    '垃圾指令密度' => 'Junk instruction density',
    '每个注入点插入的垃圾指令块数量，0 表示不插入'
        => 'How many junk instruction blocks are inserted per injection point; 0 inserts none',
    '反沙箱级别' => 'Anti-sandbox level',
    '驱动加权沙箱评分，需配合沙箱阈值使用'
        => 'Drives the weighted sandbox score and works together with the sandbox threshold',
    '内存流式解密' => 'Streaming memory decryption',
    '驻留 / 1 / 2 / 3 轮' => 'Resident / 1 / 2 / 3 rounds',
    '加密区按需解密的密钥流轮数；轮数越多，内存快照越难直接还原'
        => 'Keystream rounds used to decrypt encrypted regions on demand; more rounds make a memory snapshot harder to restore directly',
    '引爆延迟' => 'Detonation delay',
    '0 – 15000 ms（默认 2500）' => '0 – 15000 ms (default 2500)',
    '执行前等待时长；分析沙箱通常只观察很短时间，真实用户几乎无感'
        => 'How long to wait before executing. Analysis sandboxes usually watch for only a short window, while real users barely notice',
    'API 反挂钩' => 'API unhooking',
    '开启时还原磁盘 ntdll 文本并扫描 IAT 重定向'
        => 'When enabled, restores the on-disk ntdll text and scans for IAT redirection',
    '内核与 hypervisor' => 'Kernel and hypervisor',
    '<strong>驱动探针层级</strong> 0 – 3：驱动级探针深度。'
        => '<strong>Driver probe level</strong> 0 – 3: how deep the driver-level probes go.',
    '<strong>CPUID 退出代价探测</strong>：用 16 次串行 CPUID 的耗时差判定 hypervisor；关闭时只信 CPUID 厂商叶子。'
        => '<strong>CPUID exit-cost probe</strong>: decides whether a hypervisor is present from the timing gap of 16 serial CPUIDs; when off, only the CPUID vendor leaf is trusted.',
    '<strong>审计本机 hypervisor / 内核工件</strong>：只读取本机状态并打印结论，不改动文件、不需要管理员权限。'
        => '<strong>Audit local hypervisor / kernel artefacts</strong>: reads local state only and prints a conclusion, changing no files and requiring no administrator rights.',
    '两者都不信任对方自报的标志位，改用可测量的行为差异。'
        => 'Neither relies on a self-reported flag; both switch to measurable behavioural differences.',
    '环境闸门' => 'Environment gate',
    '判定是否在沙箱或无头环境中运行，分数达到阈值即拒绝执行。阈值越低越严格，也越容易误杀低配真机。'
        => 'Decides whether the program is running in a sandbox or headless environment and refuses to run once the score reaches the threshold. A lower threshold is stricter and more likely to trip on a low-end real machine.',
    '沙箱分数阈值' => 'Sandbox score threshold',
    '0 – 100（默认 40）' => '0 – 100 (default 40)',
    '无头环境分数阈值' => 'Headless score threshold',
    '0 – 100（默认 7）' => '0 – 100 (default 7)',
    '硬件下限：逻辑处理器数' => 'Hardware minimum: logical processors',
    '物理内存 (MB)' => 'Physical memory (MB)',
    '系统运行时长 (ms)' => 'System uptime (ms)',
    '屏幕宽度 / 高度 / 显示器数量' => 'Screen width / height / monitor count',
    '0 = 不检查' => '0 = do not check',
    '环境闸门只在保护项目页开启「沙箱防护」或「环境检查」时生效；否则这些阈值会被记录但不参与判定。'
        => 'The environment gate only applies when “sandbox guard” or “environment check” is on in the Protect project page; otherwise these thresholds are recorded but take no part in the decision.',
    '读取 PE 信息、嵌入水印和虚拟文件清单，<strong>不修改目标文件</strong>。'
        => 'Reads PE information, embedded watermarks and the virtual file list, <strong>without modifying the target file</strong>.',
    '动作' => 'Action',
    '输出' => 'Output',
    'PE 信息' => 'PE information',
    '架构、节表、入口与关键头字段等只读解析结果'
        => 'Architecture, section table, entry point and key header fields, parsed read-only',
    '读取水印' => 'Read watermark',
    '保护时写入的水印 / 构建标识' => 'The watermark / build marker written at protection time',
    '虚拟文件' => 'Virtual files',
    '虚拟文件容器中的文件清单' => 'The file list inside the virtual file container',
    '本机激活 ID' => 'Local activation ID',
    '当前机器的 16 位激活 ID，用于硬件绑定配置'
        => 'This machine\'s 16-character activation ID, used for hardware binding',
    '结果输出在页面下方的等宽文本区，可直接复制。典型用法：保护完成后读取水印与虚拟文件，确认输出与配置一致。'
        => 'Results appear in the monospaced text area below the page and can be copied directly. Typical use: after protecting a build, read the watermark and virtual files to confirm the output matches the configuration.',
    '记录保存在本机，直到你手动删除。' => 'Records stay on the local machine until you delete them.',
    '每条记录包含标题、详情与时间；来自每次保护运行与审计动作。'
        => 'Each record carries a title, details and a timestamp, and comes from a protection run or an audit action.',
    '支持单条删除与「清空记录」；空状态给出提示。'
        => 'Records can be deleted individually or cleared entirely; the empty state explains itself.',
    '记录与规避设置、诊断日志一样，全部保存在本机，<strong>不上传任何服务器</strong>。'
        => 'Like evasion settings and diagnostic logs, records are kept entirely on the local machine and <strong>never uploaded</strong>.',
    '设置与在线更新' => 'Settings and online update',
    '外观与界面语言设置立即生效；在线更新从 GitHub 读取已发布的客户端版本。'
        => 'Appearance and interface language apply immediately; online update reads published client builds from GitHub.',
    '外观' => 'Appearance',
    '应用主题：跟随系统 / 浅色 / 深色，默认跟随 Windows 系统设置。'
        => 'Application theme: follow system / light / dark, following the Windows setting by default.',
    '视觉主题：玻璃 / 波普 / 实验室，与官网三主题同名同义。'
        => 'Visual theme: glass / pop / lab — the same three themes, under the same names, as this site.',
    '界面语言：简体中文 / 英语。切换后立即生效并记住选择，只影响客户端界面文字，不改变构建行为。'
        => 'Interface language: Simplified Chinese / English. The change applies immediately and is remembered; it affects client interface text only and never changes build behaviour.',
    '数据与诊断' => 'Data and diagnostics',
    '运行记录、规避设置与诊断日志都保存在本机，不上传任何服务器；界面可直接打开日志目录与配置目录。'
        => 'Run history, evasion settings and diagnostic logs all stay on the local machine and are never uploaded; the interface opens the log and configuration folders directly.',
    '<strong>恢复默认规避设置</strong>：只重置对抗与规避设置，不影响项目文件和历史记录。'
        => '<strong>Reset evasion settings</strong>: resets countermeasure and evasion settings only, leaving project files and history untouched.',
    '<strong>检查更新</strong>：直接向 GitHub Releases 查询最新版本；显示当前是否已是最新。'
        => '<strong>Check for updates</strong>: queries GitHub Releases directly for the latest version and reports whether you are already current.',
    '<strong>下载更新</strong>：下载安装包并按 GitHub 提供的 SHA-256 摘要逐字节校验，校验不一致不会进入安装。'
        => '<strong>Download update</strong>: downloads the installer and verifies it byte for byte against the SHA-256 digest GitHub publishes; a mismatch never reaches installation.',
    '<strong>运行安装包</strong>：校验通过后启动安装向导。'
        => '<strong>Run installer</strong>: launches the setup wizard once verification passes.',
    '更新过程不经由本站中转；官网只承担说明与下载引导。'
        => 'Updates never pass through this site; the website only documents and points at the download.',
    '技术要点与适用范围' => 'Technical notes and scope',
    '保护流程从分析目标文件开始：识别 PE/CLR 格式、处理器架构、区段结构与 SDK 标记，再按目标能力生成构建计划。'
        => 'Protection starts by analysing the target file — PE/CLR format, processor architecture, section layout and SDK markers — and then generates a build plan from the target\'s capabilities.',
    '分层保护原理' => 'How the protection layers work',
    '<strong>区段保护</strong>：符合条件的原生代码区段（及可选资源区段）打包，按压缩收益压缩，启用加密时 XOR 编码；启动时由对应架构加载器恢复。'
        => '<strong>Section protection</strong>: eligible native code sections (plus the optional resource section) are packed, compressed when that pays off, and XOR-encoded when encryption is on; the matching loader restores them at startup.',
    '<strong>关键区域虚拟化</strong>：原生 x64 中由 SDK 标记或函数扫描选中的区域转为内部虚拟指令，由随镜像分发的解释器执行。翻译器覆盖绝大多数编译器产出的 x86-64 代码——8/16/32/64 位整数 ALU（宽度精确标志）、SSE 算术与浮点、整数 SIMD、位测试族、x87、字符串指令、CMPXCHG/CPUID/RDTSC、enter/pushfq/popfq、8 位乘除对、128 位乘除、全部条件跳转与调用；同一目标 5266 个函数实测 <strong>100.0% 的函数字节被虚拟化</strong>（chunk 全部可虚拟化、零拒绝桶）。栈帧函数的帧序言与尾声同样进 VM（push/leave/ret 全降低）；降不了的形式（AVX、cmpxchg8b 等）经原生桥执行——多返回、共享尾声、尾调用全部正确。'
        => '<strong>Critical region virtualization</strong>: on native x64, regions selected by SDK markers or the function scanner become internal virtual instructions executed by an interpreter shipped inside the image. The translator covers x86-64 code from virtually every compiler — 8/16/32/64-bit integer ALU with width-exact flags, SSE arithmetic and floating point, integer SIMD, the bit-test family, x87, string instructions, CMPXCHG/CPUID/RDTSC, enter/pushfq/popfq, 8-bit multiply/divide pairs, 128-bit multiply/divide, and every conditional jump and call; across 5266 functions in one measured target <strong>100.0% of function bytes were virtualized</strong> (every chunk virtualizable, zero reject buckets). A stack-frame function keeps its prologue and epilogue in the VM too (push/leave/ret all lowered); forms that cannot be lowered (AVX, cmpxchg8b and similar) run through a native bridge, with multiple returns, shared epilogues and tail calls all staying correct.',
    '<strong>字节码执行期解码</strong>：VM 字节码全程保持密文，解释器按 256 字节滑动窗口按需解码（计数器密钥流，第 i 字节只依赖 key/RVA/i&gt;&gt;3），内存转储在任何时刻都拿不到完整 VM 程序。每个区域有独立的物理操作码布局与密钥。'
        => '<strong>Bytecode decoded at execution time</strong>: VM bytecode stays encrypted throughout and the interpreter decodes it on demand through a 256-byte sliding window (counter keystream, where byte i depends only on key, RVA and i&gt;&gt;3), so a memory dump can never capture a complete VM program at any instant. Each region gets its own physical opcode layout and key.',
    '<strong>变异与导入保护</strong>：Ultra 管线在虚拟化前变异并对字节码追加混淆（垃圾指令注入按标志活跃性选点，分支目标在布局确定后回填）；导入保护运行时重建 IAT。<br><strong>再虚拟化</strong>：字节码可再切分为阶段并提升出二级执行块，每层独立操作码置换与密钥，最多 4 层嵌套。'
        => '<strong>Mutation and import protection</strong>: the Ultra pipeline mutates before virtualization and appends obfuscation to the bytecode (junk injection picks sites by flag liveness, branch targets are backfilled once the layout is fixed); import protection rebuilds the IAT at runtime.<br><strong>Re-virtualization</strong>: bytecode can be split into further stages and hoisted into second-level execution blocks, each layer with its own opcode permutation and key, nesting up to four levels.',
    '<strong>运行时校验</strong>：按架构与配置执行完整性校验；原生 x64 提供许可数据校验与机器标识绑定。'
        => '<strong>Runtime verification</strong>: integrity checks run according to architecture and configuration; native x64 adds licence-data verification and machine-identity binding.',
    '<strong>.NET 加密封装</strong>：受支持的托管 EXE 使用基于 XTEA 的载荷加密，由专用宿主解密、校验并启动，保留 CLR 元数据与 IL 结构。'
        => '<strong>Encrypted .NET wrapping</strong>: supported managed EXEs use XTEA-based payload encryption that a dedicated host decrypts, verifies and launches, preserving CLR metadata and IL structure.',
    '适用范围' => 'Scope',
    '目标' => 'Target',
    '支持情况' => 'Support',
    '原生 x86/x64 EXE（C/C++、Rust、Golang）' => 'Native x86/x64 EXE (C/C++, Rust, Golang)',
    '区段保护与输出处理全覆盖' => 'Full section protection and output handling',
    'SDK 区域 VM、VM 前置变异、运行时许可与机器绑定'
        => 'SDK region VM, pre-VM mutation, runtime licensing and machine binding',
    '主要面向原生 x64' => 'Primarily native x64',
    'C# / VB .NET EXE' => 'C# / VB .NET EXE',
    '加密封装；目前不提供 IL 虚拟化' => 'Encrypted wrapping; IL virtualization is not offered',
    '当前用于识别与能力提示，暂不生成保护输出'
        => 'Recognized and reported for capability purposes; no protected output yet',
    '实际支持情况以客户端构建计划与「当前目标能力」为准。产品设计参考 VMProtect 与 Themida 的组织思路，但不复现其全部功能、内部算法或保护强度。'
        => 'Actual support is whatever the client build plan and capability matrix report. The design takes organizational cues from VMProtect and Themida without reproducing all of their features, internal algorithms or protection strength.',

    // ---- SDK -------------------------------------------------------------
    'NovaProtect SDK 文档：NOVAPROTECT_BEGIN/END 标记用法、字节模式、VM 约束、汇编示例与兼容性说明。'
        => 'NovaProtect SDK docs: NOVAPROTECT_BEGIN/END marker usage, byte patterns, VM constraints, assembly examples and compatibility.',
    '在应用源码里标记需要虚拟化或混淆的函数，再用 NovaProtect 客户端打包，标记区域即被降级为 VM 字节码。未保护版本里标记是完全无副作用的 NOP。'
        => 'Mark the functions you want virtualized or obfuscated in your application source, then pack with the NovaProtect client and the marked regions are lowered to VM bytecode. In an unprotected build the markers are entirely side-effect-free NOPs.',
    '快速开始' => 'Quick start',
    '把 <code class="inline">sdk/include/novaprotect_sdk.h</code> 放进你的工程。'
        => 'Drop <code class="inline">sdk/include/novaprotect_sdk.h</code> into your project.',
    '用 <code class="inline">NOVAPROTECT_BEGIN("名称")</code> 和 <code class="inline">NOVAPROTECT_END()</code> 包住一个函数体。'
        => 'Wrap a function body in <code class="inline">NOVAPROTECT_BEGIN("name")</code> and <code class="inline">NOVAPROTECT_END()</code>.',
    '正常编译出 EXE——标记在未保护版本里是无副作用的 NOP。'
        => 'Build the EXE as usual — the markers are side-effect-free NOPs in an unprotected build.',
    '在 NovaProtect 客户端选择该 EXE，模式设为虚拟化或 Ultra，开始保护。'
        => 'Pick that EXE in the NovaProtect client, set the mode to virtualize or Ultra, and start protection.',
    '客户端扫描 BEGIN/END 字节边界、在对象编辑器列出每个区域，并把可翻译区域降级为 VM 字节码。'
        => 'The client scans the BEGIN/END byte boundaries, lists each region in the object editor, and lowers translatable regions to VM bytecode.',
    'API 参考' => 'API reference',
    '头文件 <code class="inline">novaprotect_sdk.h</code> 提供以下宏；只依赖编译器内联汇编，无运行时库、无 DLL。'
        => 'The header <code class="inline">novaprotect_sdk.h</code> provides the macros below. They rely only on compiler inline assembly: no runtime library, no DLL.',
    '宏' => 'Macro',
    '<code class="inline">NOVAPROTECT_BEGIN("name")</code>' => '<code class="inline">NOVAPROTECT_BEGIN("name")</code>',
    '在函数体内标记区域起点。x64 发出 <code class="inline">LEA RCX,[rip+0]</code> + 20 字节 NOP；x86 发出 <code class="inline">LEA ECX,[0]</code> + 20 字节 NOP。name 参数仅用于可读性，字节模式与名称无关。'
        => 'Marks the start of a region inside a function body. On x64 it emits <code class="inline">LEA RCX,[rip+0]</code> plus a 20-byte NOP; on x86, <code class="inline">LEA ECX,[0]</code> plus a 20-byte NOP. The name argument is for readability only — the byte pattern does not depend on it.',
    '标记区域终点，20 字节 NOP。' => 'Marks the end of a region, a 20-byte NOP.',
    '旧版别名，生成完全相同的字节，既有工程无需修改。'
        => 'Legacy aliases that emit byte-for-byte identical output, so existing projects need no changes.',
    '当前头文件版本字符串（如 <code class="inline">"2.2.7"</code>），可用于条件编译。'
        => 'The current header version string (for example <code class="inline">"2.2.7"</code>), usable in conditional compilation.',
    '编译器相关的内联属性宏（MSVC <code class="inline">__forceinline</code> / GCC <code class="inline">always_inline</code>）。'
        => 'A compiler-specific inline attribute macro (MSVC <code class="inline">__forceinline</code> / GCC <code class="inline">always_inline</code>).',
    '字节模式与编译器' => 'Byte patterns and compilers',
    '要求 <strong>x86 或 x64 Windows</strong> 目标（<code class="inline">_WIN32</code> / <code class="inline">_WIN64</code>），否则预处理报错。'
        => 'Requires an <strong>x86 or x64 Windows</strong> target (<code class="inline">_WIN32</code> / <code class="inline">_WIN64</code>); otherwise preprocessing fails.',
    '标记通过 <code class="inline">__asm__ volatile</code>（GCC / Clang 风格内联汇编）发出；MSVC 下使用其兼容路径。'
        => 'Markers are emitted through <code class="inline">__asm__ volatile</code> (GCC / Clang style inline assembly), with a compatible path under MSVC.',
    '检测器扫描的是<strong>固定字节序列</strong>，与宏的 name 参数无关——同一函数内不要嵌套重复标记。'
        => 'The detector scans for a <strong>fixed byte sequence</strong> that is independent of the name argument — do not nest or repeat markers inside one function.',
    '标记是位置无关的 <code class="inline">LEA</code> + NOP 滑条，不引用全局符号，链接与剥离均不受影响。'
        => 'Markers are position-independent <code class="inline">LEA</code> plus NOP sleds that reference no global symbols, so linking and stripping are unaffected.',
    '标记示例' => 'Marker example',
    '普通函数体打标记（完整示例见仓库 <code class="inline">sdk/examples/example.cpp</code>）：'
        => 'Marking an ordinary function body (full example in the repository at <code class="inline">sdk/examples/example.cpp</code>):',
    '建议用 <code class="inline">-O0</code> 或 volatile 局部变量编译标记文件，避免优化器把标记区与周边代码合并。'
        => 'Compile marked files with <code class="inline">-O0</code> or with volatile locals so the optimizer does not merge the marked region into surrounding code.',
    '手动添加函数保护（无需改源码）' => 'Add function protection without touching source',
    '除 SDK 标记外，客户端「保护」页内置 <strong>VMP 式函数扫描器</strong>：'
        => 'Besides SDK markers, the client\'s Protect page ships a <strong>VMProtect-style function scanner</strong>:',
    '对 x64 目标读取 <code class="inline">.pdata</code> 异常目录，枚举全部运行时函数（含静态函数），按 RVA 排序。'
        => 'For x64 targets it reads the <code class="inline">.pdata</code> exception directory, enumerates every runtime function (static ones included) and sorts them by RVA.',
    '列表显示名称 / 地址 / 节 / 大小 / 模式 / 可虚拟化性；支持过滤与逐个勾选。'
        => 'The list shows name / address / section / size / mode / virtualizability, with filters and per-row ticking.',
    '「添加所有函数」一键全选；批量设置模式（继承 / 虚拟化 / Ultra / 仅前置变异 / 跳过）、VM 复杂度、变异强度与激活锁定。'
        => '“Add all functions” selects everything in one click; bulk-apply the mode (inherit / virtualize / Ultra / pre-mutation only / skip), VM complexity, mutation strength and the activation lock.',
    '扫描出来的函数按<strong>完整函数区间</strong>虚拟化：帧序言与尾声/RET 同样进 VM（push/leave/ret 全降低），多返回、共享尾声、尾调用全部正确；降不了的指令形式经原生桥执行。'
        => 'Scanned functions are virtualized across the <strong>whole function interval</strong>: the frame prologue and epilogue/RET go into the VM as well (push/leave/ret all lowered), with multiple returns, shared epilogues and tail calls staying correct; instruction forms that cannot be lowered run through a native bridge.',
    '完整虚拟化的约束' => 'Constraints on full virtualization',
    '翻译器把 x86-64 翻译成 wire 指令集（145 个操作码）交给随镜像分发的解释器执行。同一目标 5266 个函数实测，5351 个 chunk <strong>全部可虚拟化、零拒绝桶</strong>，<strong>100.0% 的函数字节被虚拟化</strong>（1,589,043 / 1,589,307）。已覆盖：'
        => 'The translator turns x86-64 into a wire instruction set (145 opcodes) executed by an interpreter shipped inside the image. In one measured target, 5351 chunks across 5266 functions were <strong>all virtualizable with zero reject buckets</strong>, <strong>100.0% of function bytes virtualized</strong> (1,589,043 / 1,589,307). Covered:',
    '整数 ALU <strong>8/16/32/64 位全宽度</strong>，标志在操作数宽度上精确计算（<code class="inline">add al,bl</code> 之后的 <code class="inline">jb</code> 读到的是字节进位）；'
        => 'Integer ALU at <strong>all of 8/16/32/64-bit width</strong>, with flags computed exactly at the operand width (a <code class="inline">jb</code> after <code class="inline">add al,bl</code> reads the byte carry);',
    '移位/旋转全宽度（含 SHLD/SHRD）、MOV/MOVZX/MOVSX/LEA（含 SIB 比例变址、无基址、RIP 相对）、XCHG/XADD/PUSH/POP（帧序言与尾声同样进 VM）、<code class="inline">moffs</code> 绝对寻址；'
        => 'Shifts and rotates at full width (SHLD/SHRD included), MOV/MOVZX/MOVSX/LEA (including SIB scaled indexing, base-less and RIP-relative forms), XCHG/XADD/PUSH/POP (the frame prologue and epilogue go into the VM too), and <code class="inline">moffs</code> absolute addressing;',
    '全部条件跳转、直接/间接 JMP 与 CALL、RET（降低为间接出口）与尾调用、SETcc/CMOVcc；'
        => 'Every conditional jump, direct and indirect JMP and CALL, RET (lowered to an indirect exit) and tail calls, plus SETcc/CMOVcc;',
    'SSE 算术与浮点：加减乘除/开方/min/max × 标量与打包、位运算、全部比较谓词、16 种数据类型转换；'
        => 'SSE arithmetic and floating point: add/subtract/multiply/divide, square root, min/max in both scalar and packed forms, bitwise operations, every comparison predicate, and 16 data-type conversions;',
    '整数 SIMD、SSE 数据移动、位测试族（BT/BTS/BTR/BTC、BSF/BSR）、x87 浮点、字符串指令（含方向标志 DF）、CMPXCHG（内存形态含 LOCK）、CPUID/RDTSC/RDRAND、UD2、<code class="inline">enter</code>/<code class="inline">pushfq</code>/<code class="inline">popfq</code>、8 位乘除对、标志传送（SAHF/LAHF/STC/CLC/CMC/CLD/STD）、128 位乘除、CDQ/CQO。'
        => 'Integer SIMD, SSE data movement, the bit-test family (BT/BTS/BTR/BTC, BSF/BSR), x87 floating point, string instructions (direction flag DF included), CMPXCHG (memory form with LOCK), CPUID/RDTSC/RDRAND, UD2, <code class="inline">enter</code>/<code class="inline">pushfq</code>/<code class="inline">popfq</code>, the 8-bit multiply/divide pair, flag transfers (SAHF/LAHF/STC/CLC/CMC/CLD/STD), 128-bit multiply/divide, and CDQ/CQO.',
    '以下形态经<strong>原生桥</strong>执行——chunk 在该指令前停止、指令按原生语义在两个 VM 区之间运行、随后继续开新 chunk，函数其余部分照常虚拟化（实测目标中零出现）：'
        => 'The following forms execute through a <strong>native bridge</strong> — the chunk stops before the instruction, the instruction runs natively between two VM regions, and a new chunk then starts, with the rest of the function virtualized as usual (none occurred in the measured target):',
    'AVX/VEX/EVEX 前缀指令（长度已精确解码，桥切分位置准确）、16 位 <code class="inline">push</code>/<code class="inline">pop</code>、<code class="inline">enter</code> 嵌套帧；'
        => 'AVX/VEX/EVEX-prefixed instructions (lengths are decoded exactly, so the bridge splits in the right place), 16-bit <code class="inline">push</code>/<code class="inline">pop</code>, and <code class="inline">enter</code> nested frames;',
    '<code class="inline">cmpxchg8b/16b</code> 与寄存器-寄存器 <code class="inline">cmpxchg</code>（原子原语——任何 VM 合成都会丢跨线程原子性，必须原生执行）。'
        => '<code class="inline">cmpxchg8b/16b</code> and register-to-register <code class="inline">cmpxchg</code> (atomic primitives — any VM synthesis would lose cross-thread atomicity, so they must run natively).',
    '深度不可界定的栈深（<code class="inline">sub rsp, reg</code>，即 <code class="inline">__chkstk</code>/alloca 形态）同样经<strong>原生桥</strong>切分：该指令原生执行于两个 VM chunk 之间，前后区域继续虚拟化。'
        => 'Stack depths that cannot be bounded (<code class="inline">sub rsp, reg</code>, i.e. the <code class="inline">__chkstk</code>/alloca form) are split by the <strong>native bridge</strong> too: the instruction runs natively between two VM chunks while the regions either side stay virtualized.',
    '跳过原因在构建日志里<strong>按类计数</strong>打印（<code class="inline">VM skip summary</code>），不是静默丢弃。'
        => 'Skip reasons are printed in the build log <strong>counted by category</strong> (<code class="inline">VM skip summary</code>) rather than dropped silently.',
    '<strong>体积下限：</strong>运行时 trampoline 需要约 <code class="inline">51 + 10 × 保留寄存器数 + 16</code> 字节；解释器参数与调用约定固定保留 rax/rcx/rdx/r8–r11，区域头部只写一个 5 字节 <code class="inline">jmp rel32</code>，trampoline 本体生成到独立的可执行 arena（每区域预留 1024 字节），所以<strong>最小可虚拟化区域是 5 字节</strong>。早期版本要求区域容纳完整 trampoline（约 137 字节），现在没有这个限制。'
        => '<strong>Size floor:</strong> the runtime trampoline needs about <code class="inline">51 + 10 × reserved registers + 16</code> bytes; the interpreter arguments and calling convention reserve rax/rcx/rdx/r8–r11, the region head holds a single 5-byte <code class="inline">jmp rel32</code>, and the trampoline itself is generated into a separate executable arena (1024 bytes reserved per region) — so <strong>the smallest virtualizable region is 5 bytes</strong>. Earlier versions required the region to hold the whole trampoline (around 137 bytes); that limit is gone.',
    '区域表上限 <strong>8192</strong>（2.3.20 起放开）：这只是损坏计数的防护上限，每个描述符仍按自身区域大小做边界检查。'
        => 'The region table holds up to <strong>8192</strong> entries (raised in 2.3.20): that is only a guard against corrupted counts, and every descriptor is still bounds-checked against its own region size.',
    '关键函数直接标记或函数扫描即可完整虚拟化（含栈帧与内存访问）；手写汇编块（见下例）是体积最小、字节码最紧凑的形态，任何尺寸都能保护。'
        => 'Marking a critical function directly or capturing it with the scanner gives full virtualization (stack frames and memory access included); a hand-written assembly block (see below) is the smallest and most compact bytecode form, and any size protects.',
    '寄存器直通汇编示例' => 'Register-passing assembly example',
    '<code class="inline">sdk/examples/example_vm.S</code>——可真正虚拟化的寄存器直线型块（节选结构，完整文件见仓库）：'
        => '<code class="inline">sdk/examples/example_vm.S</code> — a register-straight-line block that really does virtualize (structure excerpt; the full file is in the repository):',
    '配套驱动 <code class="inline">sdk/examples/example_driver.c</code>，用于验证保护前后结果一致：'
        => 'The matching driver <code class="inline">sdk/examples/example_driver.c</code> verifies that results match before and after protection:',
    '构建：' => 'Build:',
    '反沙箱 / 反转储 / 环境自检' => 'Anti-sandbox / anti-dump / environment self-check',
    '打包时可在客户端独立开启三项运行时防护（详见<a href="/features/#runtime">功能详解</a>）：'
        => 'Three runtime guards can be enabled independently in the client at pack time (details in the <a href="/features/#runtime">feature reference</a>):',
    '<strong>反沙箱检测</strong>：累计评分 CPU 数、物理内存、已知沙箱模块与监控组件、RDTSCP 时序、CPU 核掩码、睡眠压缩与桌面/用户名模板，超过阈值即终止。'
        => '<strong>Sandbox detection</strong>: cumulatively scores CPU count, physical memory, known sandbox modules and monitoring components, RDTSCP timing, CPU core masks, sleep compression and desktop/username templates, and terminates past the threshold.',
    '<strong>反内存转储</strong>：校验 MZ/PE 头、区段表与 PEB 加载基址，拦截 Procdump/Minidump 后处理。'
        => '<strong>Anti-dump</strong>: verifies the MZ/PE headers, section table and PEB load base, blocking Procdump/Minidump post-processing.',
    '<strong>交互桌面环境自检</strong>：校验 CPU 数、内存、开机时长、屏幕分辨率、显示器数。'
        => '<strong>Interactive desktop self-check</strong>: verifies CPU count, memory, uptime, screen resolution and monitor count.',
    '这些只对原生 x64 生效，且默认关闭，按需开启避免误杀。'
        => 'These apply to native x64 only and are off by default; turn them on deliberately to avoid false positives.',
    '与商业 VMProtect 的关系' => 'Relationship to commercial VMProtect',
    '客户端自身与 NovaProtect 核心运行时使用商业 VMProtect SDK 做启动级虚拟化与防篡改（构建时自动链接 <code class="inline">VMProtectSDK64.a</code>，发布时附带 <code class="inline">VMProtectSDK64.dll</code>）。这是对 NovaProtect 自有 VM 引擎的补充——SDK 标记的区域由自有 wire VM 执行，两层互不替代。'
        => 'The client itself and the NovaProtect core runtime use the commercial VMProtect SDK for launch-level virtualization and tamper protection (linking <code class="inline">VMProtectSDK64.a</code> at build time and shipping <code class="inline">VMProtectSDK64.dll</code>). This complements NovaProtect\'s own VM engine — SDK-marked regions execute on the native wire VM, and neither layer replaces the other.',
    '兼容性' => 'Compatibility',
    '旧版 <code class="inline">NOVAPACK_BEGIN</code> / <code class="inline">NOVAPACK_END</code> 继续可用，字节模式不变。'
        => 'The legacy <code class="inline">NOVAPACK_BEGIN</code> / <code class="inline">NOVAPACK_END</code> still work, with unchanged byte patterns.',
    'x86 与 x64 都支持 marker 扫描；<strong>VM 翻译仅 x64</strong>。'
        => 'Marker scanning works on both x86 and x64; <strong>VM translation is x64 only</strong>.',
    '标记区域在未保护构建中为 NOP，不改变控制流、不引入依赖，可直接随源码分发。'
        => 'In an unprotected build a marked region is a NOP: no control flow change, no new dependencies, so it can ship with your source.',
    '客户端与 SDK 版本独立演进；以仓库 <code class="inline">sdk/README.md</code> 与本页为准。'
        => 'Client and SDK versions evolve independently; the repository <code class="inline">sdk/README.md</code> and this page are authoritative.',
    'SDK 源码' => 'SDK source',
    '函数保护详解' => 'Function protection details',
];
