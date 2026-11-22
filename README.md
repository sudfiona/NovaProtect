<div align="center">

# NovaProtect

**Windows EXE 保护工作台** — 把关键函数翻译成自有指令集交给内置解释器执行

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-2ea44f)
[![Version](https://img.shields.io/badge/version-3.1.5-orange)](VERSION)
[![VM coverage](https://img.shields.io/badge/VM%20byte%20coverage-100%25-brightgreen)](docs/engine-redesign.md)
![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B%20%2F%20C%23%20%2F%20x64%20ASM-9cf)

客户端 · 官网 · SDK · 安装器 · 发布工具 —— 全部开源

</div>

---

## 目录

- [这是什么](#这是什么)
- [能做什么](#能做什么)
- [架构](#架构)
- [快速开始](#快速开始)
- [用法](#用法)
- [从源码构建](#从源码构建)
- [测试](#测试)
- [仓库布局](#仓库布局)
- [开源范围](#开源范围)
- [文档](#文档)
- [安全](#安全)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

---

## 这是什么

NovaProtect 是一个 Windows PE 保护工作台。它把目标文件中选定的函数/区域**翻译成自有的指令集**，由随镜像分发的解释器执行，使关键逻辑不以可直接反汇编的原生形式出现在成品里。配合指令变异、反调试、内存保护与导入混淆，构成一套分层的代码保护方案。

它包含两部分：

- **保护引擎**（`NovaProtect.Engine.exe`）—— PE 解析、虚拟化翻译器、变异引擎、免杀体系、打包器。
- **工作台客户端**（WinUI 3）—— 项目管理、函数级保护选择、构建进度、检查工具、在线更新。

官网站点是纯静态 PHP，无后台、无数据库，可直接部署到宝塔 Nginx。

## 能做什么

### 代码虚拟化

把目标函数体翻译成 **wire 指令集**（145 个操作码），交给随镜像分发的解释器执行。

- **覆盖率 100.0%**：同一目标 5266 个 `.pdata` 函数、5351 个 chunk 实测**全部可虚拟化、零拒绝桶**，1,589,043 / 1,589,307 字节被虚拟化。指令覆盖包括 8/16/32/64 位整数 ALU（宽度精确标志）、SSE 算术与浮点（标量/打包、比较、16 种数据类型转换）、整数 SIMD、位测试族（BT/BTS/BTR/BTC、BSF/BSR）、x87、字符串指令（含 DF）、CMPXCHG、CPUID/RDTSC/RDRAND、SHLD/SHRD、moffs 寻址、`enter`/`pushfq`/`popfq`、8 位乘除对、128 位乘除、标志传送。降不了的形式（AVX、`cmpxchg8b/16b` 等）经**原生桥**执行——函数其余部分照常虚拟化。
- **栈帧函数可虚拟化**：帧序言与尾声同样进 VM（push/mov rbp,rsp/leave/ret 全降低），深度不可界定的栈深（`__chkstk`/alloca）经原生桥切分衔接——多返回、共享尾声、尾调用全部正确。
- **原生调用**：`WIRE_CALL` 在解释器内执行真实 `call`，被调方跑在解释器自己的栈上，volatile 寄存器按 ABI 装载/回收，256 字节栈参数从 guest 帧拷贝。
- **再虚拟化（4 层嵌套）**：阶段切分 + guest 块提升，每层独立操作码置换与密钥。实测同一输入 17 / 34 / 51 / 68 个描述符对应 level 1-4，四者输出一致。
- **字节码执行期解码**：字节码全程保持密文，解释器按 256 字节滑动窗口按需解码，内存转储拿不到完整 VM 程序。
- **每区域操作码置换**：区域 RVA 折叠进映射种子，每个区域有独立的物理操作码布局。
- **指令变异 + 透明谓词假跳转**：变异引擎替换指令序列，垃圾指令注入时按标志活跃性选点，分支目标在布局确定后回填。

### 免杀与对抗

一个 `EvasionConfig` 驱动六族生成器，四档预设 `off / balanced / aggressive / paranoid`，每个开关也能单独改。构建字节由 64 位种子决定——**同一颗种子两次打包得到逐字节相同的镜像**。

| 层 | 判据 | 为什么改名改不掉 |
| --- | --- | --- |
| ring 3 | PEB `BeingDebugged`、`NtGlobalFlag`、`RDTSC` 时序 | 调试器必须改这些才能调试 |
| hypervisor | `CPUID.40000000H` leaf 空间 + 厂商串、16 次串行 CPUID 的 exit 成本、VMX 屏蔽 | CPUID 必须被 trap，隐藏厂商串也躲不掉 exit 成本 |
| 驱动 | 设备对象 / 驱动服务键 / 内核模块列表 / `KUSER_SHARED_DATA` tick 连续性 | 沙箱先藏用户态进程，藏不掉自己的驱动 |

另有：反沙箱、内存流式解密、引爆延迟、反挂钩、导入加密与 IAT 重建、资源区段加密（保留图标）、完整性自校验、激活锁定。

### 工作台客户端

| 页面 | 作用 |
| --- | --- |
| 保护项目 | 选目标、调保护策略、跑构建；顶部规避摘要卡 |
| 对抗与规避 | 档位、构建签名种子、垃圾指令、反沙箱、内存流式解密、引爆延迟、反挂钩、驱动探针层级、CPUID 退出代价、环境闸门阈值；两个审计按钮直接打印本机判定 |
| 检查工具 | 对已有文件做静态检查、读取构建计划 |
| 运行记录 | 历史构建结果 |
| 更新日志 | 与 GitHub Releases 同步；离线时显示随程序打包的版本记录 |
| 设置 | 主题、在线更新、数据与诊断 |

**函数级保护**：对 x64 目标读取 `.pdata` 异常目录，枚举全部运行时函数（含静态函数），勾选即可对整个函数体做 VM 保护——**无需改源码、无需打标记**。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│  ui/                    WinUI 3 工作台（项目编辑、构建、更新）│
├─────────────────────────────────────────────────────────────┤
│  src/                   保护引擎                              │
│    packer*.cpp          PE 打包器：区段/导入/资源/重定位      │
│    vm_engine.cpp        x86-64 → wire 翻译器 + 解释器装配     │
│    vm_obfuscate.cpp     字节码优化器：垃圾指令/扁平化         │
│    vm_revirt.cpp        再虚拟化：阶段切分 + guest 块提升     │
│    disasm.cpp           x86-64 反汇编器（翻译器的解码前端）   │
│    mutation.cpp         指令变异引擎                          │
│    evasion_*.cpp        六族免杀生成器 + 三层环境探测         │
│    anti_debug / api_unhook / mem_loader / crypto_layers       │
├─────────────────────────────────────────────────────────────┤
│  runtime/               随镜像分发的运行时                    │
│    prot64.c             x64 wire 解释器（freestanding C）     │
│    stub.S / stub32.S    x64 / x86 引导桩                      │
│    mutkern.S            变异内核模板                          │
│    managed_host.cpp     CLR 托管宿主（加密 EXE）              │
├─────────────────────────────────────────────────────────────┤
│  sdk/                   集成头文件 + 示例                      │
│  website/               纯静态 PHP 官网（部署指 public/）      │
│  installer/             Inno Setup 安装器                      │
│  tools/                 发布/校验/逆向调试工具                 │
└─────────────────────────────────────────────────────────────┘
```

**一次保护构建的链路**：目标 PE → 函数/区域选择 → x86-64 解码 → wire 翻译（含再虚拟化）→ 字节码混淆 → 变异 → 免杀层注入 → 加密打包 → 引导桩装配 → 受保护 EXE。

## 快速开始

### 1. 安装客户端

从 [GitHub Releases](https://github.com/sudfiona/NovaProtect/releases) 或[官网](https://nova.fbi.plus/download)下载 `NovaProtect-Setup-<version>.exe`，双击安装。

客户端安装包发布在 GitHub Releases；官网的 `/download` 与 `/client-updates` 直接指向该仓库。更新器直读 GitHub API，下载重定向逐跳主机钉扎到 `github.com` / `objects.githubusercontent.com` / `*.githubusercontent.com`，并按资产 `sha256:` 摘要（或 `SHA256SUMS`）校验 64 位十六进制 SHA-256 与确切字节数。

### 2. 从源码构建

前置依赖：

| 依赖 | 用途 |
| --- | --- |
| MinGW-w64（gcc/g++/as/ld） | 引擎与运行时（C / C++ / x64 汇编） |
| .NET 10 SDK | WinUI 3 客户端 |
| Inno Setup 6/7 | 安装器打包（仅发布时需要） |

```powershell
# 全量构建：引导桩、保护运行时、变异内核、托管宿主、引擎、WinUI 客户端
powershell -File build.ps1 -All

# 只构建引擎（最快，用于验证翻译器/打包器）
powershell -File build.ps1 -Cli
```

`build.ps1` 开关：`-Stub` `-Prot` `-Mut` `-ManagedHost` `-Cli` `-WinUi` `-All`。

> **商业 VMProtect SDK 是可选依赖。** 缺失时构建自动降级为无操作标记（`NOVAPROTECT_VMP_STUB`），无需任何手工干预。想加那层额外保护，自行购买授权后把 SDK 放到 `third_party/vmprotect/`，构建会自动检测并使用。

### 3. 保护一个目标

```
1. 打开客户端 → 保护项目 → 选择目标 EXE/DLL
2. 「保护」页勾选函数（.pdata 自动枚举），或在源码里用 SDK 标记
3. 调保护模式与对抗档位 → 开始构建
4. 构建日志与构建计划记录完整 argv 与规避参数，可追溯产物
```

## 用法

### SDK 标记（改源码）

```cpp
#include "novaprotect_sdk.h"

int verify_license(const char* key)
{
    NOVAPROTECT_BEGIN("verify_license");
    // 希望被保护的逻辑
    NOVAPROTECT_END();
    return result;
}
```

标记在未保护的构建里是惰性的（几条 `nop`），编译后把 EXE 拖进客户端即可。旧名 `NOVAPACK_BEGIN/END` 继续可用，字节模式不变。

### 函数扫描（不改源码）

客户端「保护」页对 x64 目标读取 `.pdata` 异常目录，枚举全部运行时函数（含静态函数），按 RVA 排序，显示名称 / 地址 / 所在节 / 大小 / 是否导出 / 是否含栈帧。支持一键全选、批量设置保护模式、VM 复杂度与变异强度。

### 命令行（引擎）

引擎是客户端调用的构建后端。免杀与对抗参数：

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

`-evasion <档位>` 会把整个 `EvasionConfig` 重写成该档位默认值，所以客户端先发 `-evasion`，再发逐字段覆盖。`-hv-audit` / `-kernel-audit` 打印本机判定（判定依据、周期数、逐条痕迹），`-kernel-driver-out` 输出可交给 WDK 的 ring-0 源码。

种子贯通整个打包流程：载荷密钥、VM 操作码置换、变异引擎、保护运行时、IAT 密钥、构建 id 都由它派生。

> **版本一致性硬约束**：客户端调用握手要求签名清单里的版本号与引擎编译期 `NOVAPROTECT_PRODUCT_VERSION` 逐字相等。升版必须同时跑 `tools\version.ps1 -Action Sync` 并重建 `NovaProtect.Engine.exe`，否则引擎以 `[gate] rejected` 拒绝启动。

## 从源码构建

完整发布链路：

```powershell
# 1. 打包前跑回归
powershell -File tests/regress.ps1

# 2. 客户端：版本检查 -> 全量构建 -> Inno Setup -> release.json -> E2E 契约冒烟
powershell -File tools/package-client-release.ps1 -RunTests

# 3. 官网：单包 + ZIP 布局/哈希/页面链接校验
powershell -File tools/package-website-php.ps1

# 4. 开源源码包（引擎 + 客户端 + 官网，剔除商业 SDK 与签名私钥）
powershell -File tools/package-github-source.ps1
```

版本策略：`tools/version.ps1` 管理 `VERSION`、`version-lock.json` 与源码摘要。**源码变更后必须先递增版本号再构建**，否则版本策略检查会拒绝；发布验证完成后 `-Action Seal` 封版。

## 测试

```powershell
powershell -File tests/regress.ps1          # 端到端回归（保护→运行→比对输出）
```

| 测试 | 覆盖 |
| --- | --- |
| `tests/regress.ps1` | 全链路：x64/x86 保护、许可证、水印、图标/清单保留、VM 虚拟化、三层再虚拟化、字节码篡改检测 |
| `tests/vm_engine_test.cpp` | 翻译器差分测试：native 执行 vs VM 执行逐寄存器比对，73 个用例（含原生桥几何断言） |
| `tests/vm_revirt_test.cpp` | 再虚拟化：阶段切分、guest 块提升、4 层嵌套等价性 |
| `tests/vm_obfuscate_test.cpp` | 字节码优化器：复杂度 0-9 下的语义保持与分支落点 |
| `tests/mut_engine_test.cpp` | 指令变异引擎：542 项替换等价性 |
| `tests/antidebug_test.cpp` | 反调试生成码真跑：32 项（检测触发、寄存器保持、TLS 回调） |
| `tests/evasion_test.cpp` / `evasion_runtime_test.cpp` | 免杀生成器 366 项 + 执行级 132 项（子进程真跑，独立 oracle 比对） |
| `tools/test-driver-emit.ps1` | ring-0 驱动生成源码：parse 级 8 项 + WDK 真编译链接 12 项 |
| `tools/test-client-gates.ps1` | 客户端闸门：7 项篡改/信任拒绝 + 正向 UI 控制 |
| `tools/vmcoverage.cpp` | 虚拟化覆盖率测量 + **字节码流完整性校验**（逐指令精确走表） |

翻译器还带两项自检：`tools/check_wire_sync.py` 交叉核对「翻译器会发出的每个操作码在运行时都有 handler」（防止静默空操作），`tools/vmwhy.cpp` 定位单个函数的翻译停止点。

## 仓库布局

| 路径 | 内容 |
| --- | --- |
| `src/` | 保护引擎：VM 引擎、再虚拟化、打包器、变异、反调试、免杀体系、加密层 |
| `include/` | 引擎头文件：VM 指令集、线格式表、PE 结构定义、打包器接口 |
| `runtime/` | 运行时源码：x64 解释器、引导桩汇编、变异核、托管宿主 |
| `ui/` | WinUI 3 客户端 |
| `website/` | 纯静态 PHP 官网（`public/` + `lib/`；旧后端 `app/`、`deploy/` 保留未引用） |
| `sdk/` | 集成头文件与示例 |
| `installer/` | Inno Setup 安装脚本 |
| `tools/` | 发布、校验与逆向调试工具 |
| `tests/` | 回归与验证测试源码 |
| `research/` | 逆向研究工具与对比脚本 |
| `docs/` | 设计文档、验证报告、部署文档 |

## 开源范围

**这份源码可以完整构建出保护引擎和客户端。** 引擎、客户端、官网、SDK、安装器与发布工具全部在内。详见 [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md)。

不随仓库分发的内容（法律或安全原因，不是"藏起来的功能"）：

| 内容 | 原因 |
| --- | --- |
| `third_party/vmprotect/` | 商业授权，禁止再分发；缺失时构建自动降级为无操作标记 |
| 签名私钥 | 一次性签发凭据，泄漏即失守 |
| 引擎与宿主二进制、安装包 | 构建产物，属于 Releases |
| `tests/_reg/` 回归样本、微步分析报告与 PCAP | 证据不是源码，生成它们的脚本已开源 |

裁剪由 `tools/package-github-source.ps1` 强制执行，不是手工约定：它断言引擎源码确实在包里、商业 SDK 与私钥确实不在包里；`tools/audit-github-source.ps1` 对成品包做独立复核。

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/manual.md`](docs/manual.md) | 产品说明与使用手册 |
| [`docs/engine-redesign.md`](docs/engine-redesign.md) | VM 引擎设计：指令集、翻译规则、再虚拟化 |
| [`sdk/README.md`](sdk/README.md) | SDK 集成：标记 API、函数扫描、虚拟化约束 |
| [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md) | 开源范围与可构建性说明 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本变更记录 |
| [`docs/exceed-vmprotect-roadmap.md`](docs/exceed-vmprotect-roadmap.md) | 与商业保护器的能力对比与路线 |

## 安全

- 受保护镜像的字节码全程密文，执行期按需解密；篡改字节码会在执行时被检测（`tests/regress.ps1` 有专门用例）。
- 客户端完整性：`client-integrity.manifest` + `.sig` 双文件签名，启动时校验，缺一即拒。
- 官网纯静态、无后台、无数据库；所有响应带 `Cache-Control: no-store`。
- 更新器从 GitHub Releases 直连，校验 64 位 SHA-256 与确切字节数，重定向主机钉扎到 `github.com` / `objects.githubusercontent.com` / `*.githubusercontent.com`。
- 发现安全问题请勿开公开 issue，走 [GitHub Security Advisories](https://github.com/sudfiona/NovaProtect/security/advisories) 私下报告。

## 参与贡献

1. Fork 并创建特性分支。
2. **先跑 `tests/regress.ps1`**——它是端到端的，会真的打包并运行受保护样本。
3. 改了翻译器/运行时，`tests/vm_engine_test.cpp` 的差分用例是最快的验证路径（native vs VM 逐寄存器比对）。
4. 改了版本相关内容，跑 `tools\version.ps1 -Action Bump` 并遵守版本策略。
5. 提 PR 时说明改动动机与验证方式。

代码风格：C++17；引擎与运行时无异常、无 RTTI（freestanding 运行时不链接 libc）；注释解释「为什么」而不是「做了什么」。

## 许可证

[MIT](LICENSE) © 2026 NovaProtect
