# NovaProtect

Windows EXE 保护工作台。官网与下载：<https://nova.fbi.plus>

NovaProtect 把目标 PE 中的选定函数/区域翻译成自有指令集并交给内置解释器执行，配合变异、反调试、内存保护与导入混淆，使关键逻辑不以原生形式出现在成品里。

> **本仓库不包含保护引擎源码。** VM 指令集、字节码解释器、二次虚拟化器、加密层与 X64 引导桩属于专有实现，不在本仓库内。这里公开的是**接入层、客户端 UI、官网源码与发布工具**。详见 [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `sdk/` | 集成头文件与示例：用 `NOVAPROTECT_BEGIN/END` 标记要保护的函数 |
| `ui/` | WinUI 3 客户端（项目编辑器、保护页、构建进度、更新检查） |
| `website/` | 官网源码（纯静态 HTML/CSS/JS，宝塔 Nginx），无后台、无数据库 |
| `installer/` | Inno Setup 安装器脚本 |
| `tools/` | 发布工具：客户端打包、网站打包、包校验、版本管理 |
| `docs/` | 产品说明、部署文档与验证报告 |

## 快速开始

### 1. 用 SDK 标记函数

```cpp
#include "novaprotect_sdk.h"

int verify_license(const char* key)
{
    NOVAPROTECT_BEGIN("verify_license");
    // 希望被虚拟化的逻辑
    NOVAPROTECT_END();
    return result;
}
```

编译后把 EXE 拖进客户端，选择「虚拟化」或「Ultra」模式。

### 2. 或者用函数扫描（无需改源码）

客户端「保护」页对 x64 目标读取 `.pdata` 异常目录，枚举全部运行时函数（含静态函数），勾选即可对整段函数体做 VM 保护。

### 3. 安装客户端

从官网下载：<https://nova.fbi.plus/download>

当前版本号见 [`VERSION`](VERSION)。客户端安装包发布在 GitHub Releases（<https://github.com/sudfiona/NovaProtect/releases>），站点的 `/download` 与 `/client-updates` 直接对接该仓库，仓库地址写在服务器上的 `github.json`（打包自 [`website/github.json`](website/github.json)）：

```json
{ "repo": "sudfiona/NovaProtect" }
```

客户端更新器读的是同一个仓库：`ui/Models/ProtectionOptions.cs` 里的 `ProductInfo.GitHubRepository`、`GitHubReleasesUrl`、`GitHubLatestReleaseUrl` 与它保持一致。改仓库时这三处要一起改，否则站点和客户端会指向不同的发布源。

`/api/releases/current` 与 `/api/releases/current/download` 保持在本站同源，作为 GitHub 的镜像端点。桌面版更新器要求同源下载路径、64 位十六进制 SHA-256 和确切字节数，因此这一步不能省：端点从 GitHub 取版本号与更新说明，安装包在首次请求时镜像到本地并计算 SHA-256，之后复用。若 GitHub 资产自带 `sha256:` 摘要，则直接采用该摘要并校验镜像文件。

## 免杀子系统（2.4.0 起）

一个 `EvasionConfig` 驱动六族生成器，四档预设 `off / balanced / aggressive / paranoid`，每个开关也能单独改。
字段定义见 [`include/evasion.h`](include/evasion.h)，版本变更见 [`CHANGELOG.md`](CHANGELOG.md)。

```
-evasion <off|balanced|aggressive|paranoid|0-3>   -no-evasion
-junk <0-8>        -anti-sandbox <0-3>      -detonate-delay <ms>
-memstream <0-3>   -unhook <0|1>
-hv-exit-cost <0|1>          -kernel-level <0-3>
-hv-audit          -kernel-audit          -kernel-driver-out <file>
-evasion-reseed    -evasion-seed <hex>
-evasion-manifest-out <file>   -evasion-manifest-in <file>
-evasion-audit     -white-plan <host>
```

每次构建的字节由 64 位种子决定：`-evasion-reseed` 现场取熵（手动刷新），
`-evasion-seed` 复现指定构建，两个 manifest 开关用来导出/复用签名清单。
种子与 `build_tag` 会写进构建日志和 `PackResult`。

种子贯通整个打包流程（`Packer::buildSeed()`）：载荷密钥、VM 操作码置换、变异引擎、
保护运行时、IAT 密钥、构建 id 都由它派生。因此同一颗种子两次打包得到**逐字节相同**的镜像，
不指定种子则每次不同。

### 层级（2.6.0 起）

| 层 | 判据 | 为什么改名改不掉 |
| --- | --- | --- |
| ring 3 | PEB BeingDebugged、NtGlobalFlag、RDTSC 时序 | 调试器必须改这些才能调试 |
| hypervisor | `CPUID.40000000H` leaf 空间 + 厂商串、16 次串行 CPUID 的 exit 成本、VMX 屏蔽 | CPUID 必须被 trap，隐藏厂商串也躲不掉 exit 成本 |
| 驱动 | 设备对象 / 驱动服务键 / 内核模块列表 / `KUSER_SHARED_DATA` tick 连续性 | 沙箱先藏用户态进程，藏不掉自己的驱动 |

`-hv-audit` 与 `-kernel-audit` 打印本机判定（判定依据、周期数、逐条痕迹）。
`-kernel-driver-out` 输出可交给 WDK 的 ring-0 源码：MSR `3AH`、hypervisor leaf、
`KeQueryPerformanceCounter` 与 rdtsc 交叉校验，paranoid 档附 `PsLoadedModuleList` 自摘链。

规避侧同层配套：时间源走 `KUSER_SHARED_DATA` 而非系统调用（少一次 VM exit）、
vendor 探针折叠为单次 CPUID、探针用哈希解析导出不留 IAT 项、不加载驱动不写注册表。

### 界面（客户端）

| 页面 | 作用 |
| --- | --- |
| 保护项目 | 选目标、调保护策略、跑构建；顶部一张规避摘要卡，右边「调整」跳到对抗与规避 |
| 对抗与规避 | 档位、构建签名种子、垃圾指令、反沙箱、内存流式解密、引爆延迟、反挂钩、驱动探针层级、CPUID 退出代价、环境闸门阈值；两个审计按钮直接打印本机判定 |
| 检查工具 | 对已有文件做静态检查、读取构建计划 |
| 运行记录 | 历史构建结果 |
| 更新日志 | 与 GitHub Releases 同步；离线时显示随程序打包的版本记录 |
| 设置 | 主题、在线更新、数据与诊断（打开日志/配置目录、恢复默认规避设置） |

`-evasion <档位>` 会把引擎的整个 `EvasionConfig` 重写成该档位默认值，所以客户端先发
`-evasion`，再发逐字段覆盖，否则用户调的值会被档位默认值盖掉。构建结束时界面会把完整
argv 打进日志，并连同 `evasion` / `environment` 一起写进构建计划 JSON，事后可追是哪套参数
压出的文件。

注意有一条硬约束：客户端调用握手要求签名清单里的版本号与引擎编译期
`NOVAPROTECT_PRODUCT_VERSION` 逐字相等，所以升版必须同时跑
`tools\version.ps1 -Action Sync` 并重建 `NovaProtect.Engine.exe`，否则引擎会以
`[gate] rejected` 拒绝启动。

### 验证

```
build\test\evasion_test.exe         366 项：生成器 / 随机化 / 跨种子唯一性
build\test\evasion_runtime_test.exe 132 项：执行级 —— 子进程真跑每条桩，独立 oracle 比对
tools\test-driver-emit.ps1            8 项：驱动源码原样过 C 前端（替身 ntddk.h）
```

运行版本先编译：

```
g++ -std=c++17 -O1 -g -municode -Iinclude -Isrc -o build\test\evasion_runtime_test.exe ^
  tests\evasion_runtime_test.cpp src\evasion*.cpp src\junk_emitter.cpp src\api_unhook.cpp ^
  src\mem_loader.cpp src\white_launcher.cpp src\pe_lib.cpp src\disasm.cpp ^
  -static -static-libgcc -static-libstdc++ -lbcrypt -limagehlp
```

覆盖内容：反沙箱/反调试桩在真 CPU 上执行并对照 CPUID、PEB、时序的独立判据；hypervisor
三层探针逐种子对照 `CPUID.40000000H.EAX` 直读与独立 16 次 CPUID 计时；内核痕迹扫描在本机
逐条列出 40 个候选；静态免杀打在 `System32\notepad.exe`（真 MSVC 镜像）上；API unhook 打在真
`ntdll.dll` 上并逐字节还原；白利用计划对 System32 的 10 个宿主全覆盖。校验和用系统自带
`MapFileAndCheckSumW` 复核。

驱动当前状态准确表述：**能编译、能链接、能签名、链能验，加载未验证**。
`tools/build-driver-wdk.ps1` 用 WDK `10.0.28000.0` + MSVC 真编译真链接（plain 4608 /
paranoid 5120 字节，0 警告，PE subsystem = NATIVE），`tools/sign-driver.ps1` 用自签证书
签名并验链。加载自签驱动要 `bcdedit /set testsigning on` 加重启，本版本不动机器的启动
配置，所以内核态实际运行行为这一格是空的。

| 模块 | 文件 | 状态 |
| --- | --- | --- |
| 静态免杀（Rich/时间戳/段名/PDB/填充/签名/校验和） | `src/evasion_static.cpp` | **已接入** `Packer::pack` 落盘前阶段 |
| hypervisor 层（vendor / exit cost / VMX 屏蔽） | `src/evasion_hypervisor.cpp` | **已接入** NPP1 `bit15` + 运行时探针 |
| 驱动层（设备 / 服务 / 模块 / tick） | `src/evasion_kernel.cpp` | **已接入** NPP1 `bit16` + 运行时探针 |
| 花指令 | `src/junk_emitter.cpp` | 生成器就绪 |
| 动态探针与宿主评分 | `src/evasion_dynamic.cpp` | 生成器就绪，输出可直接进 prot64 blob |
| 分区加密加载计划 | `src/mem_loader.cpp` | 生成器就绪（`NPMP` 表） |
| API unhooking | `src/api_unhook.cpp` | 生成器就绪（`NPUH` 表 + 还原驱动源码） |
| 签名宿主白利用 | `src/white_launcher.cpp` | 计划渲染就绪（10 个宿主） |
| ring-0 驱动发射器 | `src/evasion_kernel.cpp` | **已接入**：WDK 真编译真链接真签名 |

NPP1 旗标 `bit15`/`bit16` 已由打包器按档位翻转，实测 paranoid 档产物标志 `0xE2A9`。
花指令、加载计划、unhook、白利用仍是引擎侧生成器，部署开关未翻转 —— 这一栏按实际接入
程度写，避免把"纸面能力"当已经生效来算。

`-evasion-audit` 是只读体检，不做"已修复"声明，输出 Rich header、PDB 路径、Authenticode 目录、
段尾零填充字节数、逐段熵（> 7.2 标 `packed-looking`）与高危导入名，用来和外部扫描器对账。

## 能力边界

NovaProtect 只处理它**确实能证明**的能力，不用语言标签包装格式支持：

| 目标 | 状态 |
| --- | --- |
| x64 原生 PE | 完整支持（虚拟化、变异、多区域） |
| x86 原生 PE | 支持（不含 x64 虚拟机） |
| .NET / CLR | 安全封装，**不是** IL 虚拟化 |
| ARM64 | 只读识别，不提供保护 |

### 分析环境对抗（x64 运行时）

四类开关可独立组合，也可一起开：

| 开关 | 命令行 | 作用 |
| --- | --- | --- |
| 沙箱环境检测 | `-sandbox-guard` | 累加式评分：虚拟化厂商 CPUID、vCPU/内存、进程规模与父进程、无输入时长、模板化机器名、注入模块路径、调试器家族。达到 `-sandbox-threshold`（默认 40）且有强证据时阻断 |
| 微步特征识别 | 随 `-sandbox-guard` 生效 | 额外四路独立证据：加载模块名、进程名、注册表足迹（`SOFTWARE\ThreatBook`、`SOFTWARE\Weibu`、`SOFTWARE\WeibuData`）、机器名/用户名。任一路命中即为**强证据**，可单独触发阻断，配置充足的专用分析设备同样拦得住 |
| 交互桌面自检 | `-env-check` | 桌面分辨率、显示器数、CPU/内存/开机时长低于阈值时阻断，`-env-threshold`（默认 7）控制门限 |
| 进程自隔离 | `-self-isolate` | 保护后的程序在自己的进程里正常运行，其他工具读不到它：见下 |
| 延时复测抽查 | `-audit-recheck`（`-sandbox-guard` 默认开启） | 启动后才附加的监控会被后续抽查抓到：见下 |

`-self-isolate` 的三层机制，全部 best-effort，主机拒绝某一层时其余照常运行：

1. **进程 DACL 改写**：通过 `NtSetSecurityObject(DACL_SECURITY_INFORMATION)` 写入针对 `WinWorldSid` 的 DENY ACE，覆盖 `PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION`、`PROCESS_CREATE_THREAD`、`PROCESS_DUP_HANDLE`、`PROCESS_SUSPEND_RESUME`。这些权限对任何主体的新 `OpenProcess` 一律拒绝。
   同一条 ACL 里再补 ALLOW ACE 授予 `PROCESS_TERMINATE`、`PROCESS_QUERY_INFORMATION`、`PROCESS_QUERY_LIMITED_INFORMATION`、`SYNCHRONIZE`，DENY 排在前面优先匹配。**只写 DENY 会连结束权限一起拒掉，留下任务管理器都杀不掉的残留进程**，这是实测后补上的。
2. **线程隐藏**：`NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0)`。缓冲区必须传 `NULL, 0`，传 4 字节标志会得到 `STATUS_INFO_LENGTH_MISMATCH`。
3. **扩展点注入封锁**：`NtSetInformationProcess(ProcessMitigationPolicy=0x34)` 置 `ProcessExtensionPointDisablePolicy`，切断 AppInit_DLLs 式注入。

实测对照（同一台真机）：

```
[read    ] DENIED err=5 (want 5)          <- 外部读内存被拒
[terminate] ALLOWED (task-manager path intact)
[query-lim ] ALLOWED (visible in task manager)
```

隔离之后进程自身的线程、堆、文件 IO、模块枚举全部正常。

### 延时复测抽查（`-audit-recheck`）

启动时只采样一次，对**启动后才附加**的监控是结构性盲区：在线分析流水线正是让样本先解包，再注入 agent 开始录制。`-audit-recheck` 因此另起一个工作线程，45 秒后开始、每分钟复测一轮、持续到程序退出，命中即走阻断路径：

**默认成对启用。** 启动采样和延时复测是一个检查的两半：只看启动的守卫看不到后来附加的监控，没有守卫的复测也没有比较基准。留给调用方自行配对的结果是产出「纸面上受保护」的镜像，所以开启 `-sandbox-guard` 会自动布防复测线程；`-no-audit-recheck` 显式关闭仍然生效，旧行为可达。UI 侧同步：勾选「沙箱环境检测」会自动勾上「延时复测抽查」，但加载已保存的项目配置时不覆盖用户手动取消的选择。

| 复测项 | 判据 |
| --- | --- |
| 后注入模块 | 是否出现从用户可写目录加载的模块（`np_injected_module_paths`） |
| 厂商模块 | 是否出现启动时不存在的厂商命名模块（`np_vendor_module_hit`） |
| 句柄突增 | 句柄数超过启动基线 120 个以上（agent 持有本进程句柄） |
| 调试堆 | `PEB+0xBC` 的 `NtGlobalFlag & 0x70` 在启动后出现（调试器附加） |
| 时钟失配 | `GetTickCount64` 与 `GetTickCount` 偏差超过 2 秒（录制/时间扭曲钩子） |
| 深度复测 | 每 5 轮重测一次 Sleep 压缩与磁盘型号（约 120 ms 一次，故不每轮跑） |

循环无终止轮次：布防后一直存在，直到程序退出。两个工作线程互相监督——对方的存活取自内核线程对象的 signaled 状态，而不是心跳。

**为什么必须用内核对象而不是心跳。** 实测：杀掉一个工作线程时，它正持有 loader lock；幸存线程随后卡在模块枚举里，心跳不再推进，也永远走不到判定点——监督机制被它本该发现的那件事本身击败。改从内核对象取状态，并把检查放在探针**之前**（此时没持有任何锁），顺序依赖才消失。杀掉任一线程都会触发阻断。

只在该开关与 `-sandbox-guard` 同时开启时才布防。任一项读不到值时不触发，缺测不会造成误报。

一个真实的教训：最初用「模块数量增加 > 2」判定后注入，实测失败——加载 3 个 DLL 后计数只从 28 走到 30（加载器去重），而合法懒加载也会让计数波动。改为判定**加载路径**后，从 `%TEMP%` 加载模块时 `injected_now` 立刻 0→1，稳态保持 0。

另一个坑：基线变量写成 `= 0xFFFFFFFFu` 会进入 `.np_data`，把 `.np_data` 扩大 16 字节并推走 `.np_bss`，触发 `build.ps1` 的 flat-layout 不变式（`.np_bss` 必须紧贴 blob 末尾）。改为零初值落入 `.np_bss`（只增尺寸、不移 VMA）后通过。

VM 解释器处理纯寄存器、直线型 x86-64 子集。以下形式会被**安全跳过**（保留原生代码，功能不受影响）：

- 访问 `RSP`/`RBP` 或内存（`[reg+disp]`、RIP 相对寻址）
- 非 `REX.W` 的 32 位操作数形式
- `CALL`/`RET`/`PUSH`/`POP`/`IMUL`/`movabs`、带 index 的 `LEA` 等解释器不支持的指令

需要真正虚拟化关键函数时，使用 `sdk/examples/example_vm.S` 的寄存器直通汇编块。块长需容纳运行时 trampoline（约 `51 + 10×保留寄存器数 + 16` 字节），函数体至少约 137 字节才可能被虚拟化。

## 部署官网

站点是纯静态文件，没有 PHP、没有数据库、没有后台。解压网站包后：

```bash
bash install.sh --check-package   # 只读校验包布局与 SHA-256，不需要 root
bash install.sh                   # 放文件、切槽位、写 Nginx 配置、逐页验证
```

升级就是再跑一次 `install.sh`，旧槽位保留为 `previous`，随时可 `bash deploy/rollback.sh`。

详见 [`website/README.md`](website/README.md) 与 [`website/deploy/README.md`](website/deploy/README.md)。

## 发布工具

```powershell
# 客户端：版本检查 -> 全量构建 -> Inno Setup 安装包 -> release.json -> 本地 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1

# 打包前先跑回归
pwsh -NoProfile -File .\tools\package-client-release.ps1 -RunTests

# 网站：单包，并校验 ZIP 布局、哈希与页面链接
pwsh -NoProfile -File .\tools\package-website.ps1
pwsh -NoProfile -File .\tools\verify-website-package.ps1

# 生成本公开源码包
pwsh -NoProfile -File .\tools\package-github-source.ps1
```

客户端打包需要 MinGW-w64（`g++`/`gcc`/`ld`/`objcopy`）、Inno Setup 6 或 7 与 .NET SDK（更新契约 smoke 用 fixture transport，不需要站点）。**保护引擎源码不在本仓库，因此从本仓库无法构建出完整的保护器**——上述脚本面向拥有完整源码树的维护者。

## 版权

客户端与官网源码以 [MIT](LICENSE) 许可开源：可自由使用、修改、分发、商用，保留版权声明即可。

开源范围是 `ui/`、`website/`、`sdk/`、`installer/` 与 `tools/`。**保护引擎不属于开源范围**——VM 指令集、字节码解释器、二次虚拟化器、加密层与 x64 引导桩是专有实现，只以编译产物形式分发。范围细节见 [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md)。

第三方组件遵循各自许可：VMProtect SDK 为商业授权，不随本仓库分发；Inno Setup 见 `installer/`；Windows App SDK 与 .NET 运行时遵循 Microsoft 条款。

## 安全

发现安全问题时请勿公开提交 issue，通过官网联系维护者。
