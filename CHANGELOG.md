# 更新日志

本文件记录 NovaProtect 客户端与站点的版本变更。站点 `/client-updates` 的更新说明取自
[GitHub Releases](https://github.com/sudfiona/NovaProtect/releases)，发布时把对应版本的
小节内容贴进 Release 正文即可。

> **说明（2026-11-22 重建）**：本文件的历史小节曾在一次编码操作失误中丢失（UTF-8 被当 GBK
> 读取后重写，`tools/unmangle.py` 可还原这类损坏）。3.1.0 及更早的小节当日依据仓库内现有
> 记录重建（`STATUS.md`「已完成」、`ui/Services/ChangelogFallback.cs`、
> `docs/release-notes-client-2.6.0.md`、`website/public/data/releases.json`、安装包版本资源、
> `docs/engine-redesign.md`），**并非 GitHub Releases 原文逐字恢复**：版本号、日期与变更
> 事实以上述记录为准，措辞可能与当时发布正文有出入。无确切发布日记录的小节不标日期，
> 顺序按版本号。3.1.1 只是过渡测试构建（`test-only-core-3.1.1`，未出安装包），并入 3.1.2
> 发布，无独立小节。

---

## 3.2.5 — 2026-11-23（客户端界面中英文切换）

这版只动客户端，引擎与保护管线没碰。三套主题收尾之后，最扎眼的缺口剩下语言：界面文字全是中文写死的，`lang.en` 这类别名只在壳层生效，一进页面又变回中文，导航里甚至直接露出 `nav.protect` 这种内部标识。

做法沿用官网那套「中文原文即键」：页面里照旧写中文，`Localizer.T` / `Localizer.F` 拿整句去 `LocalizerStrings` 查英文，查不到就原样返回中文——所以漏翻只会显示中文，不会白屏，也不会露出键名。视觉树上的文字由 `ApplyTo` 在页面加载后、以及每次切语言时重写一遍，页面本身不需要加任何标记。

- 侧栏六个页面的导航名称与页头提示补齐；切到英文后显示页面名，不再露出 `nav.*` 这类内部标识。
- 设置页按当前语言重绘诊断路径与已有更新提示，路径、文件名、版本号保持原值。
- 保护项目页的能力状态列改用对应语言的文字。
- 代码里拼出来的句子（列表摘要、计划明细、冲突提示）在调用点用 `F` 翻译；占位符按整句模板查表，`{0}`、`{1}` 的位置不会错位。

顺手修掉本轮改动自己引出的一个真问题。`ProtectionPlanner`、`ProtectionOptions`、`EvasionOptions`、`FunctionScanner` 现在都要调 `Localizer`，而三个无头 smoke 项目（planner、ui-logic、update-client）是直接编译这些 UI 源文件的，却拿不到 WinUI 类型——回归一跑就是 27 处 `CS0103`，连打包里的更新契约冒烟都编不出来。把 `Localizer` 拆成两半：`Localizer.cs` 只留字符串核心（语言状态、`T`/`F`、别名表、持久化），`Localizer.VisualTree.cs` 放视觉树遍历。这样三个 smoke 项目编译的是客户端真正发布的那套翻译逻辑，而不是另写一份桩。拆完回归全绿。

验证：`tests/regress.ps1` **ALL PASS（67 项 OK，零 FAIL、零 SKIP）**；更新契约冒烟 51 项通过（GitHub API 形状、摘要强制、重定向主机钉死、下载计量）；安装包 61,616,158 字节，SHA-256 `cb3023ba…`，图标按 `ui/Assets/NovaProtect.ico` 逐帧哈希比对。

诚实边界：中英文在全部页面上的往返切换仍待逐页人工验收——自动化只覆盖到编译、启动、主窗口、检查工具页与本机 ID 读取。英文表缺项时按设计回落到中文原文，所以看到个别中文标签属于待补翻译，不是渲染错误。

## 3.1.5 — 2026-11-22（主题条还是椭圆 + 打开设置会跳回玻璃）

上一版把三套主题重写完了，用起来还剩两个很扎眼的毛病。这版只动客户端，引擎没碰。

顶栏「玻璃 / 波普 / 实验室」外面包了一层轨道，圆角写成了 999，整条像一颗胶囊。改成跟官网一样按主题给圆角——玻璃 12、波普 4、实验室 6——不再是椭圆。

更烦人的是：明明切到了波普，一点「设置」，整个界面又变回玻璃，下拉框却还显示着波普。查下来是设置页 XAML 里写死了 `SelectedIndex="0"`，页面一构造就触发 `SelectionChanged`，把主题强行 Apply 成 glass，连 `ui-theme.txt` 也一起写坏了。现在构造时只回填下拉框、不真正切主题；下拉框和当前主题一致时直接 return。

WinUI Release 构建 0 警告 0 错误。手动验过：切波普/实验室 → 开设置 → 主题和下拉框都还在。

## 3.1.4 — 2026-11-22（虚拟化覆盖率 → 100.0%：解码流失步修复、PUSH/BT 组修复、帧序言入 VM）

本轮把两个口径的覆盖率都推到 **100.0%**（同一目标 `NovaProtect.Engine.exe` 5266 个 .pdata 函数：5351 个 chunk **全部可虚拟化、零拒绝桶**；`virtualized bytes` **1,589,043 / 1,589,307**）。测量工具 `tools/vmcoverage.cpp` 改为 chunk 级模型（stub 尺寸/溢出建模、原生桥字节不计入），3.1.3 引擎在该口径下的起点为 88.1%（3.1.2 发布口径的 91.5% 是旧模型数字）。全程按 0 BUG / 0 漏洞标准推进，抓出并修掉 **12 个引擎缺陷**（另修客户端主题体系 2 项，见下），其中 3 个会让已发布版本的虚拟化结果或保护输出出错（XALU 整数空操作、POR 映射错误、反调试第 5 参栈槽错位），其余为解码流失步、翻译缺口与本轮新特性的内部缺陷。

### 正确性缺陷（会影响保护结果，不止覆盖率）

- **`push reg/imm` 虚拟化恒存 0**：PUSH 降低读 `src` 操作数，而解码定向把被压值放 `dst`——每条虚拟化 push 都向栈写 0，帧序言保存的 `rbp` 被毁、降低后的 `leave/pop` 原样恢复出 0。改为按 `dst` 定向（reg/imm/mem 三形分别降低），未知形态直接拒绝而非静默存 0。（本轮新特性内部缺陷，未出过发布版本。）
- **`bt r/m, imm8` 被误判「写 RSP」**：0F BA 组的 ModRM.reg 是操作码扩展（/4 = BT），解码层把它当寄存器编成了幻影 RSP，栈深度守卫视作不可界定的 rsp 写而在该指令处切分——`bt rax, 5` 的 chunk 被切成空 HALT，整段静默不执行。`fixupOperands` 对 BT 族（0F A3/AB/B3/BB/BA）重定 dst←rm（位串）、src←索引（寄存器或 imm8），翻译器同步；`bts rsp,…` 这类真实写 rsp 的形态反而落入守卫被正确切分。
- **XALU 整数 SIMD 空操作（影响 3.1.2/3.1.3）**：PADDB 等整数打包运算进 XALU 后什么都不算直接过——结果静默错误。补齐整数通道。
- **POR 映射键写成 0xE1（影响 3.1.2/3.1.3，PSRAW 的编码）**：POR 被派发到 PSRAW 的语义。改键 0xEB。
- **反调试生成码第 5 参栈槽错位一格（影响 2.4.0 起所有带反调试的保护输出）**：`genNtQueryInfoProcess` 把 ReturnLength 输出指针写到 `[rsp+0x28]`，而 Windows x64 ABI 的第 5 参在 `[rsp+0x20]`——被调的 `NtQueryInformationProcess` 从未初始化的 0x20 槽读到栈残留垃圾作输出指针。垃圾是坏指针时 API 调用静默失败（ProcessDebugPort/Flags/Object 检测恒报「干净」，检测形同失效）；垃圾是可写地址时内核往该地址写 ReturnLength，**悄悄砸栈**、随后在无关代码处崩溃（`antidebug_test` 即在打印处读到被改写的 name 指针而崩，新旧构建同点复现）。槽位改回 0x20 后 `antidebug_test` 32/32。
- **标志恢复插错位置覆盖 rax**（VM-MISMATCH 0x202 根因）：出口 `popfq` 的位置覆盖了 rax 槽。
- **客户端主题体系重写（颜色非全局 + 胶囊圆角 + 三主题辨识度）**：`StaticResource` 在解析期把画刷对象冻结，而 `NovaTheme.Apply` 用**换对象**方式更新资源——切换主题后 29 处冻结引用仍显示旧主题色；卡边框渐变键还被纯色对象顶掉（类型都不符）；页面背景渐变两端写死浅色。改为**原位变更对象**（顶层资源与 Light/Dark 两个主题字典一并命中）+ 值类 token 换发后翻转 RequestedTheme 刷新。在此之上按「冷雾·热浪·深空色温对撞 × Y2K 液态铬/1960s 海报/1990s 终端时代质感」融合重写三主题（剔除气刷铬、错版阴影、扫描线、全等宽字等噱头）：玻璃＝冰蓝薰衣草冷雾+全息渐变+22px 软圆角+人文细体；波普＝珊瑚/柠檬/品红平涂+**2px 黑描边**+2px 直角+Bahnschrift 粗黑体；实验室＝黑紫深空+磷光绿/紫外+发丝线+2px+Cascadia Mono 数据等宽。圆角/字体/描边/图标前景全部 token 化（ThemeResource），页面 XAML 不再写死。
- **`66 F7` TEST 立即数宽度**：按 32 位读 imm16 多吞两字节，后续指令边界全错——幻影出 VEX/moffs 两个大拒绝桶共 50KB，是覆盖率损失的最大来源（失步即拒绝，行为未错）。
- **`0F 31` rdtsc 被误加 ModRM**：同类失步。
- 另：`imul` 16 位立即数、`xchg` RIP 相对内存、PMULLW(0xD5) 映射、rdseed/rdrand 前缀判定放宽。

### 覆盖率机制

- **帧序言计入虚拟化**：`push` / `mov rbp,rsp` / `sub·and·lea rsp` 全部经访客栈槽（VM slot 4）降低，原生序言不再裁剪；trampoline 自身的 `push rbp` 与虚拟化序言写同一槽同一值。
- **RET/LEAVE 降低**：`leave` = mov rsp,rbp + pop rbp；`ret` = LOADQ 返回地址 + ADDRADDI rsp + 间接 EXITJMP。极小叶函数（5 字节 stub 窗口吞掉原生尾声岛）走 `allowIslands=false` 重试全降低。
- **原生桥切分**：深度不可静态界定的 `sub rsp, reg`（`__chkstk`/alloca 形态）在该指令前停止翻译，packer 开新 chunk、桥指令原生执行于两个 VM 区之间，桥前后 chunk 的 flag/df 由入口/出口标志同步衔接。写 RSP 的函数不再是「整函数放弃」。
- **解码补完**：x87（D8-DF）、字符串（A4-AF，DF 变为真实 VM 状态）、moffs（A0-A3）、0F BC/BD（bsf/bsr/tzcnt/lzcnt）、0F B0/B1（cmpxchg）、0F A2（cpuid）、0F 0B（ud2）、0F A4/A5/AC/AD（shld/shrd）、0F C3-C7、0F 00-3F 段 ModRM 例外清单（rdtsc 等单字节指令）、F6/F7/FE/FF 组操作数定向、CPUID/字符串隐式操作数、`ret imm16`(C2) 与 `enter imm16,imm8`(C8)、**VEX（C4/C5）与 EVEX（62）精确长度**（AVX 不进 VM，但长度必须对，否则原生桥会切在指令中间）。
- **原生桥泛化**：翻译器遇到降不了的指令不再放弃整个函数——chunk 在该指令前停止、packer 把它原生执行于两个 VM 区之间、随后继续开新 chunk。`sub rsp,reg`（`__chkstk`/alloca）走的就是同一机制；现在 AVX/VEX、`cmpxchg8b/16b`、寄存器-寄存器 `cmpxchg`、16 位 `push/pop`、`enter` 嵌套帧（level>0）各自只花掉自己那几字节。`cmpxchg8b/16b` 刻意留在桥上：它是原子原语，任何 VM 合成都会丢跨线程原子性。
- **新 wire 降低**：WIRE_BITSCAN / X87 / STR / CMPXCHG / CPUID / RDTSC / UD2 / RDRAND / SETDF / SHLD / PUSHF / POPF / MULB / DIVB（wire 指令集 131 → 145 个逻辑操作码）。`pushfq/popfq` 经 flag 文件的 RFLAGS 布局往返；`mul/div r/m8` 的 AX 对语义与 AH 驱动的 CF/OF 由 WIRE_MULB/DIVB 一次完成；`enter imm16,0` 按 CPU 实测语义（imm16 原样分配、无舍入）降为 push/mov/sub 三步。

### 验证

`vm_engine_test` **73/73**（新增帧序言虚拟化、bt 组立即数、ret/leave/ret imm16/enter/pushfq·popfq/mul8·div8 降低回归与桥几何断言）、`vm_revirt_test` 58/58、`mut_engine_test` 542/542、`vm_obfuscate_test` OK、`antidebug_test` **32/32**、evasion 套件 366+132+3、`tests/regress.ps1` **ALL PASS（含 x86 六项，零 SKIP）**、五语言 E2E（C++/C#/VB/Rust/Go）保护后输出与基线一致。字节码流完整性校验（逐指令精确走表至 HALT）全绿。

### 诚实边界

- 原生桥指令字节不计入虚拟化字节（实测 264 字节间隙 = 桥指令 + 1 个不可解析的 .pdata 范围条目 + 尾部不对齐）。
- x87 经 `WIRE_X87` 按 (esc,modrm) 原始编码查表执行，语义等价原生（不建模 x87 栈）。
- 经原生桥执行（不进 VM、行为正确、函数其余部分照常虚拟化）：AVX/VEX/EVEX、`cmpxchg8b/16b`（保跨线程原子性）、寄存器-寄存器 `cmpxchg`、16 位 `push/pop`、`enter` 嵌套帧。实测目标中这些形式零出现，故字节间隙仅 264。
- 口径：「虚拟化覆盖率」= 可虚拟化 chunk 占比（100.0%）；「vm 字节覆盖率」= `virtualized bytes`（100.0%）。测量直接调用真实翻译器，不可通过改测量工具刷数。

## 3.1.3 — 2026-11-22（开源发布：标准 README、SDK 文档与官网文案对齐真实能力）

把开源包的说明层与实际能力对齐。3.1.2 的引擎改动不变，本版只动文档与开源打包。

- **`README.md` 完全重写**为 GitHub 标准结构（标题/徽章/这是什么/能做什么/架构/快速开始/用法/构建/测试/仓库布局/开源范围/文档/安全/贡献/许可证），逐项对应真实功能：VM 覆盖率 91.5%、指令类别、再虚拟化 4 层、字节码执行期解码、三层环境探测、确定性构建。
- **`sdk/README.md` 重写**：补齐 API 参考（`NOVAPROTECT_BEGIN/END`、编译器支持矩阵、旧名兼容）、函数扫描、虚拟化覆盖表、**保留为原生**清单及原因、区域尺寸下限（5 字节）、常见问题。
- **官网 SDK 页**同步：删掉过时的「只虚拟化到第一个 RET」「区域表上限 64」「至少 137 字节」「纯寄存器直线型子集」，换成 91.5% 覆盖与真实保留清单。
- **官网首页与功能页**：补上函数扫描、栈帧函数虚拟化、91.5% 覆盖、再虚拟化；把已被替换的「字节码组合加密（RC4 + XOR + 字节加法）」改成现行的「全程密文 + 执行期按需解码」。
- **`docs/manual.md`** 修正与 `docs/REPOSITORY-SCOPE.md` 的矛盾（原文称「本仓库不包含保护引擎源码」，实际是完整开源）；目录表补上 `src/` `include/` `runtime/` `tests/`。
- 开源源码包：`tools/package-github-source.ps1` 产出 `artifacts/github-source/NovaProtect-<version>-source.zip`，引擎源码在内、商业 SDK 与签名私钥在外，`tools/audit-github-source.ps1` 独立复核。

## 3.1.2 — 2026-11-22（虚拟化字节 51.7% → 91.5%：SSE 算术/浮点 + 宽度精确 ALU）

本轮把「能虚拟化的都虚拟化」推到 **91.5%**（同一目标 `NovaProtect.Engine.exe` 5260 个 .pdata 函数，1,475,160 / 1,612,577 字节），并补齐 SSE 算术/浮点指令集。全程按 0 BUG / 0 漏洞标准推进，期间抓出并修掉 **8 个既有正确性缺陷**（见下）。

### 引擎：WIRE_NALU —— 宽度精确 ALU（覆盖 232KB 拒绝字节）

此前 8/16 位 ALU 走「宽位运算 + `WIRE_INSB/INSW` 拼接」，结果正确但留下**宽位标志**；后续任何分支一读标志就被整段拒绝（`cat 31 op 0/133` 等四个桶合计 232KB）。新操作码 `WIRE_NALU` 用一个选择器字节 `(宽度<<4)|操作` 覆盖 ADD/SUB/ADC/SBB/AND/OR/XOR/NOT/INC/DEC/NEG/SHL/SHR/SAR/ROL/ROR × 8/16/32/64 位：结果按宽度回写（8/16 拼接、32 零扩展、64 覆盖），**标志在该宽度上计算**。窄标志从此精确，分支不再被拒。

- `WIRE_NALU` 同时接管 32 位移位/旋转与内存目的地移位（此前 32 位旋转显式拒绝、内存目的地移位直接拒绝）。
- **`inc/dec` 走 `ADDI/SUBI` 会写 CF**，而 x86 的 INC/DEC 从不碰 CF —— `stc; inc rax; adc rbx,0` 读到的是加法进位而非 1。现在 INC/DEC 保持 CF 不变，64/32 位同样修复。

### 引擎：SSE 算术 / 浮点（覆盖 210KB 拒绝字节）

新操作码 `WIRE_XALU` / `WIRE_XALUI`（操作与格式各占一字节）+ XMM 拼接语义，落地：

- **标量/打包浮点**：ADD/SUB/MUL/DIV/MIN/MAX/SQRT × ps/pd/ss/sd；MIN/MAX 按 Intel 语义（任一为 NaN 取源、双零取源符号）。
- **位运算**：AND/OR/XOR/ANDN（ps/pd）。
- **比较**：CMPPS/CMPPD/CMPSS/CMPSD 的 8 个谓词 + COMISS/COMISD/UCOMISS/UCOMISD（写整数标志，后续 `jbe` 等正确）。
- **转换**：CVTSI2SS/SD、CVT(T)SS/SD2SI、CVTSS2SD/CVTSD2SS、CVTDQ2PS/PS2DQ/PD2PD 等 16 种编码；`cvt*` 舍入到最近偶数，`cvtt*` 截断，溢出/NaN 给整数不定值。
- **整数 SIMD**：PCMPEQB/W/D/Q、PCMPGTB/W/D/Q、PUNPCKL/H*、PACKSSWB/SSDW/USWB、PADDB/W/D/Q、PSUBB/W/D/Q、PAND/POR/PXOR/PANDN、PSHUFD/PSHUFLW/PSHUFHW、PSLL/PSRL/PSRAW/D/Q、PSLLDQ/PSRLDQ、PMOVMSKB。
- **数据移动补全**：MOVQ（`66 0F D6` / `F3 0F 7E` / `66 REX.W 0F 7E` 三条编码方向各异）、MOVSS/MOVSD 取存（寄存器形态拼接低半、内存形态清零高位）、MOVHPS 存储、MOVD/MOVQ 往返。

### 引擎：其余拒绝桶

- `BT/BTS/BTR/BTC`（`WIRE_BITOP` + `WIRE_SETCF`）：只写 CF，ZF/SF/OF/PF 原样保留；寄存器形态索引按 5/6 位掩码，内存形态是纯位偏移（位可落在所寻址字之外——架构语义）。
- 一元 `MUL/DIV/IDIV`（`WIRE_MULQ`/`WIRE_DIVQ`/`WIRE_IDIVQ`）：RDX:RAX 128 位积与 128:64 商，带符号形式按高位修正；32 位编码在 64 位对上建模后拆回 EDX:EAX。
- `SAHF/LAHF`、`STC/CLC/CMC`（`WIRE_SETCF`）、`CLD/STD`（无操作：VM 不执行读 DF 的指令）。
- `CDQ/CQO`：`WIRE_ADDRSHRI` 是 LEA 式无标志算术右移，符号复制不动标志。
- 两操作数 `IMUL` 的内存源、组 1 `ADC/SBB` 立即数形式。

### 解码器

- **`66 81` / `66 C7` / `66 69` 的立即数宽度**：16 位操作数形态此前按 32 位读立即数，多吞 2 字节导致**整流失步**——后续每个指令边界都错位。按操作数宽度取 2/4 字节后对齐。
- 组 1 `0x80-83` 补 `/2 ADC`、`/3 SBB`；`0x99` CDQ/CQO、`0x9E/0x9F` SAHF/LAHF、`0xF8/F9/F5/FC/FD`、`0F A3/AB/B3/BB/BA` BT 族分类。
- 0F 前缀的 ModRM 覆盖补到 `0xA3/AB/B3/BB/BA`、`0xC2/C6`、`0xD0-0xFE`；`0x70-0x73/C2/C4/C5/C6/BA/A4/AC` 与 0F3A 形态的尾随 imm8；`0F 77`（EMMS，无 ModRM）从 SSE 带里排除。

### 抓出并修掉的既有正确性缺陷（8 项）

1. **字节码静默截断（严重）**：`if (partial) { emit(splice); b8(d); b8(s); } else emit(...); b8(d); b8(s);` 缺大括号，两处（部分宽度 reg-reg `mov`、`xchg reg,mem`）。操作数字节被无条件写入，解释器把垃圾字节当操作码——未知操作码即停止，其后整段字节码被静默丢弃。约 7/8 的运行显示正常（垃圾字节碰巧解码为「未用」槽位），随机排列映射成真操作码时才踩中寄存器，表现为**间歇性寄存器值损坏**。已加**字节码流精确走表断言**（逐指令走到最后一个 HALT、不多不少），与结果比对正交。
2. **XMM 操作数约定不一致（静默空操作）**：翻译器发 `20+i`，运行时按 `< 16` 校验并当数组下标用 —— 全部 XMM 数据移动一直是 no-op。现按 `NP_XIDX` 映射；XMM 临时槽也从裸 15/14 改为 20+15/20+14。
3. **XALU 选择器溢出**：`(fmt<<4)|op` 只有 4 位操作码空间却定义了 27 个操作 —— 转换/打包/移位等根本编不进去。改为操作、格式各占一字节。
4. **`WIRE_COUNT` 低于最高操作码**：打包器按 `logical < WIRE_COUNT` 建映射，最后一个操作码会被重编码成物理 0。已加 `static_assert` 锁死。
5. **`inc/dec` 写了 CF**（见上）。
6. **`66 81` 立即数宽度**导致整流失步（见上）。
7. **`shl r/m8, 20` 下溢**：计数宽于操作数时 `a >> (bits-cnt)` 无符号下溢成巨大移位（UB）。
8. **`F3 REX.W 0F 7F`（MOVDQU 带被忽略的 REX.W）被当成 MOVQ 只存 8 字节**；MOVQ 形式已由 0xD6 / F3 0F 7E 分支接管，此处判断删除。

另修 `WIRE_SBBI/ADCI` 操作数表（长度 10 却声明 1 个操作数）、`wireWritesReg` 漏 INSB/INSW/SBB/ADC 族。

### 验证

- 虚拟化字节：**51.7% → 91.5%**（`tools/vmcoverage` 直接调用真实翻译器实测）。
- 全部 5260 个函数的**字节码流完整性检查**：0 个畸形流。
- **翻译器↔运行时操作码同步检查**：发出的每个操作码都有 handler（0 个静默空操作）。
- `tests/regress.ps1` → **ALL PASS**（62 项）。
- `vm_engine_test` **65/65**，连跑 15 次稳定（修掉间歇性缺陷前约 8 次中 1 次失败）。
- `vm_revirt_test` 58/58、`vm_obfuscate_test` OK、`mut_engine_test` 542/542。
- 诚实边界：x87（21KB）、字符串指令（17KB）、`BSF/BSR`、`CMPXCHG`（需原子性）、`CPUID/RDTSC/moffs`、AVX/VEX 仍未翻译——VM 不建模 x87 栈与 DF，强行翻译会出错。这些是**覆盖率缺口不是缺陷**：翻译器拒绝它们，函数整体留在原生代码，行为正确。剩余 8.5% 未虚拟化字节里，约一半属于这几类，其余是结构性的（`body writes RSP`、超小叶函数的原生 epilogue）。

### 已知待办

- ~~`CHANGELOG.md` 历史小节与 `STATUS.md` 正文在一次编码操作失误中受损~~ → **2026-11-22 已处理**：本文件历史小节依仓库内记录重建（见文首说明），`STATUS.md` 修复 `?` 乱码并补齐 2.5.0 起的条目。

## 3.1.0 — 2026-11-21（handler 盐、分节密码 v2、8/16 位 ALU 补完）

3.0.0 的函数体虚拟化可用后，本版加逆向对抗强度与精确标志语义。

- **handler 盐**：每个虚拟化区域把 region RVA 折入映射种子，对 handler 槽做操作码全排列——同一逻辑操作码在不同区域落到不同 handler，静态还原单个区域的映射无法复用到别的区域。
- **分节密码 v2**：32 字节重复 XOR 升级为「位置 + 节 RVA」双因子密钥流（自逆，加解密同序）；完整性校验改为常开——运行时发现密文被篡改即硬停，不再执行被改过的代码。x64 与 x86 两套桩同步。
- **8/16 位 ALU 补完**：宽位运算 + 回写拼接 + 标志活跃度分析，窄位结果正确落位；移位类仍安全拒绝（拒绝即整函数留原生，行为正确）。
- **验证**：`tests/regress.ps1` ALL PASS（含密码 v2 往返与篡改检测用例）、`vm_engine_test` 33/33、`vm_revirt_test` 58/58、`mut_engine_test` 542/542、反调试用例 PASS、五语言 E2E。
- 安装包 `NovaProtect-Setup-3.1.0.exe` 61,554,038 字节，SHA-256 `f303f84f9637057b0c71a272860fb75bf2819869399f8c05c8819f893d3371a7`。

## 3.0.0 — 2026-11-21（重大更新：函数体虚拟化）

把虚拟化从「SDK marker 指定的区域」推进到**整个函数体**：序言/尾声留在原生，函数体整体进 VM。

- **函数体虚拟化**：新增 `WIRE_EXITJMP`（尾声跳转）、`WIRE_CALL`（受控外调）、`WIRE_IMGADD`（映像基址计算）；寄存器文件 16 → 20 槽。覆盖率 9.5% → **54.6% 函数 / 228,173 字节（14.3%）**。
- **无 RET 函数处理**：尾跳切割 + 尾声孤岛，不依赖「遇到第一个 RET 就停」的旧假设。
- **NP → NP 二次打包兼容**：对已保护目标再次打包不破坏。
- **解码器修复**：C6/C7/86/87 分类、字节操作数宽度、SIB r12 索引、`0F 1F` 多字节 NOP。
- 代码评审抓出 8 项缺陷并清零。

## 2.6.0 — 2026-11-04（对抗与规避页、构建可追溯）

把引擎里已有但界面够不着的对抗能力做进客户端 UI。发布类型：客户端。

- **新增「对抗与规避」页**：规避档位四档（关闭 / 均衡 / 激进 / 偏执，四列对比表）、构建签名种子（留空取系统熵 / 固定值可复现 / 「每次构建重新随机」开关 / 零种子拦截）、动态对抗项（垃圾指令密度 0–8、反沙箱 0–3、内存流式解密轮数 0–3、引爆延迟 0–15000 ms、API 反挂钩）、内核与 hypervisor（驱动探针层级 0–3、CPUID 退出代价探测）、环境闸门（沙箱/无头阈值 + 6 项硬件下限）、两个本机审计按钮（只读，不需管理员）。
- **新增「更新日志」页**：GitHub Releases 直读（跳过草稿与非语义标签），离线回落到 `ChangelogFallback.cs` 打包记录并标注来源；纯文本渲染不注入 HTML；超 16 行截预览。
- **构建可追溯**：日志新增 `规避: <档位> · <详情>` 与 `命令行: <完整 argv>` 两行；构建计划 JSON 新增 `evasion` / `environment` / `commandLine` 字段。`-evasion` 档位参数必须放在逐字段覆盖之前，否则会把用户调的值盖掉。
- **其他**：默认页改为「保护」；设置页新增「数据与诊断」；项目文件 schema 2 → 3（旧项目平滑迁移）；跑之前校验零种子。
- **4 项 UI 修复**：导航到新页面崩溃（`InitializeComponent` 期间事件触发、处理器读未构造控件）、双击「开始保护」崩溃（`ContentDialog` 串行化）、规避摘要卡档位名重复、档位明细表改四档对比。
- **验证**：MSBuild 0 错；523 文件完整性签名；63KB 目标 63,362 → 145,408 字节；UPDATE-SMOKE 51 项；501 断言 0 失败。安装包 `NovaProtect-Setup-2.6.0.exe` 61,117,278 字节，SHA-256 `b0410486927bb909cecfdf9a1089d986034428e8445bd845158aa9b0f13bb297`。
- **已知限制**（发布说明原文）：驱动加载未验证（能编译链接签名验链，加载未验证）；无 SDK marker 也未勾函数的普通 EXE 走原生执行；偏执档兼容性风险最高，发布前须实测；反沙箱/反调试阈值过严会误判低配真机与远程桌面。

## 2.5.1 — 2026-11-03（tick 连续性阈值修复）

- **修复 tick 连续性检测把 15.6 ms 时钟节拍当毫秒计**——真实机器几乎全被误判为分析环境。改为按节拍换算。
- 沙箱防护 / 环境检查与延时复测的配对默认开启；PE 版本资源同步。

## 2.5.0 — 2026-11-02（环境闸门与自隔离）

- **进程自隔离**：进程 DACL 拒绝 OpenProcess / 句柄复制；线程对调试器隐藏；`ProcessExtensionPointDisablePolicy`。
- **延时复测 worker**：引爆延迟后做二次环境判定。
- **硬件下限**：逻辑处理器数、物理内存、系统运行时长、屏幕宽高、显示器数量。

## 2.4.0 — 2026-11-02（免杀子系统接入打包管线）

免杀能力首次从引擎参数走进打包管线：

- 反沙箱加权评分、垃圾指令、内存流式解密、API unhook、静态特征清理（Rich 头 / DOS stub / 时间戳 / 节名 / slack 填充 / PDB）、构建签名种子。
- 客户端更新说明的离线回落源 `ui/Services/ChangelogFallback.cs` 自本版起收录。

## 2.3.33 — 2026-10-30（全量重建 + 客户端完整性签名）

- **全量重建**：stub、保护运行时（blob 35,424 字节）、变异内核、托管宿主、引擎、WinUI 全部重编，CLIENT-INTEGRITY-SIGNED（521 文件，RSA-3072 / SHA-256）。
- **沙箱对抗强化**；延时复测默认开启（`0x2000` 配对位，`-no-audit-recheck` 退出）；PE 版本资源同步。
- 安装包 61,023,046 字节，SHA-256 `9b6d31b57859e57a23c3117a8f372918c49e42e19e310d9f081549ee38d49326`。

## 2.3.22（覆盖率第二轮：IMUL、蹦床与区域头）

- 两操作数 `IMUL r/m`（`0F AF`）`needs_modrm` 修正 + `mulFlagsPending` 标志安全性。
- 蹦床 arena 定长 `kTrampStride=384`，区域头只留 5 字节 `jmp rel32`，区域最小长度 137 → **5 字节**。
- 修复 `51+20×regs` 越界。

## 2.3.21（覆盖率第一轮：SIB 与 disp32）

- 无基址 SIB `LEA`、`[disp32]` 绝对寻址；`has_sib` 与 RIP 相对寻址的区分修正。

## 2.3.20（区域数量上限 64 → 8192）

- `kMaxVmRegions` 64 → 8192，运行时 `np_vm_install` 同步上限；大目标不再被 64 个区域截断。

## 2.3.19（UI 日志与引擎拒绝摘要）

- UI `AppendLog` O(N²) 拼接 → 20 ms 缓冲定时器 + 12 万字符截断，长时间构建不再卡死界面。
- 引擎 `vmSkip()` 拒绝原因聚合计数，4,832 行逐条日志压成 29 行摘要。

## 2.3.11 — 2026-10-26（二次虚拟化多层嵌套）

- **多层嵌套**：`vmRevirtualize` + `WIRE_GSTAGE` 递归，level 1..4（`-revirt-level`），guest 深度 8。
- **修复**：stage/guest 表偏移改从反向表基址计算；`regPerm` 覆盖全 20 槽；按载体类型的最小连跑阈值（stage 6 / guest 4）。
- 验证：回归 ALL PASS（含 x64_revirt_l1..l3：17/34/51 块）、UPDATE-SMOKE 72 项、升级包 0 个 exe。版本封存 digest `CE9665D1…`。

## 2.3.10 — 2026-10-26（不透明谓词、handler 表置乱、再虚拟化）

引擎加固三件套（`docs/engine-redesign.md` 记为本版）：

- **不透明谓词假跳**：分支 fixup + 标志活跃度感知插入 + 哨兵 HALT（`tests/vm_obfuscate_test.cpp`）。
- **handler 表置乱**：`np_handlers[]` 改为运行时 `np_vm_init_handlers()` 填充——静态初始化在 blob 拷贝后会残留链接期地址。
- **`EnableRevirtualization`**：stage 拆分 `vmSplitStages`、guest 块提升 `vmLiftGuestBlocks`、`np_vm_guest` / `np_ghandlers`，ISA 45 → 82，`wire_table.h` 单一来源。

## 2.3.9（VM 运行时加固 + 中文路径）

- **字节码常驻密文**：256 字节滑窗按需解码，计数器密钥流以 key / RVA / i>>3 为参；运行时每 4096 条指令轮询 PEB `BeingDebugged` 并投毒寄存器；移除 RC4 / VirtualProtect 特征字符串，blob 20,000 → 19,776 字节。
- **中文路径修复**：`std::filesystem::u8path`，非 ASCII 安装/输出路径不再出错。

## 2.3.2 — 2026-10-22（函数扫描模式 + 三处引擎修复）

- **函数扫描**：VMP 风格 `.pdata` RUNTIME_FUNCTION 枚举（含 static 函数），`-func StartRva-EndRva-Mode-Vm-Mut-Lock`，`FunctionSource=ScanFunction`。
- 引擎修复：REX.W 立即数符号扩展、x64 32 位操作数门控、蹦床 caller-saved 寄存器。

## 2.3.1（反沙箱拦截崩溃修复）

- 反沙箱拦截崩溃修复：prot64 blob 数据表绝对指针 → 定宽字符矩阵，并在 `build.ps1` 加扫描断言。
- PHP E2E 72 项通过。

## 2.3.0 — 2026-10-20（一机一码三因子）

- **一机一码三因子**：CPUID + 卷序列号 + MachineGuid，每 UTF-16 单元 FNV-1a，`main.cpp` 与 `prot64.c` 双端一致。

## 2.2.7 — 2026-10-19（打包链修复）

- `version.ps1` UTF-8 BOM 修复；Inno 60 字符截断防护。
- `client_release_upload_smoke.py` 从 version.iss / VERSION 推导版本；`start-website-test.ps1` HTTPS_PROXY 修复。
- 源码包排除表修复（`VMProtectSDK.h` 曾穿透过滤器）。

## 站点（官网）线 2.2.12 — 2.3.0 —— 并行版本序列（约 2026-10 下旬 ~ 11 月上旬）

官网站点曾有独立版本号序列（与客户端同号不同物）；#32 起两线版本解耦，`website/VERSION` 冻结在 2.3.0。以下依 `STATUS.md` 重建：

- **ASP.NET Core → PHP 迁移**（#1）：站点重写为 PHP。
- **2.2.12**：账号 / 会员体系移除，管理端路由契约固定。
- **2.2.13–14**：SSH 管理员密码重置（`reset-admin-password.php`，`--locate` 探测顺序）。
- **2.2.18–21**：WAF 安全的 `NPCHUNK1:` 512KB 分块上传（不走 multipart / 文件名 / .exe / MZ 首字节，`/api/admin/release/{begin,chunk,finish,abort}`）；同通道离线升级 ZIP；精简升级包 58.7MB → 261KB；405 修复（`endpoint()` 的 `/api/` 前缀守卫）。
- **部署**：`bash install.sh`（PHP-FPM 探测、槽位切换、SHA-256 校验、回滚）。
- **#32 版本解耦**：站点版本不再跟随客户端。
- **#33–34 GitHub Releases 迁移**：`/download` 与 `/client-updates` 改指仓库；更新器直读 GitHub API，下载重定向主机钉扎到 github.com / objects.githubusercontent.com / *.githubusercontent.com，摘要取 asset 的 `sha256:` 或 SHA256SUMS。
- **2.3.0（站点）纯静态改造（#35）**：现站为**纯静态 PHP**（服务端模板渲染，无数据库 / 后端 / 登录 / Cookie），`public/` + `lib/`；打包 `tools/package-website-php.ps1` → `artifacts/website-release/`，部署即把站点根指到 `public/`（目录索引，无需伪静态规则）。**记录更正**：#35 称旧后端 `app/`、`deploy/` 已删除并归档到 `artifacts/website-backend-legacy-2.2.31/` —— 与仓库现状不符（两目录仍在 `website/` 下，归档目录不存在）。以 `website/README.md`「历史说明」为准：旧脚本**保留但不再被新站引用**。
