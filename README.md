<div align="center">

<img src="ui/Assets/NovaProtect.png" width="128" alt="NovaProtect" />

# NovaProtect

Windows PE 保护工作台 — 函数级虚拟化、代码变异、反调试与加壳，配一个 WinUI 3 桌面客户端。

[![License](https://img.shields.io/badge/license-MIT-3DA639.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4.svg)](#系统要求)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4.svg)](https://dotnet.microsoft.com/)
[![WinUI](https://img.shields.io/badge/WinUI-3-0067C0.svg)](https://learn.microsoft.com/windows/apps/winui/winui3/)
[![Version](https://img.shields.io/badge/version-2.6.0-brightgreen.svg)](CHANGELOG.md)
[![Website](https://img.shields.io/badge/website-nova.fbi.plus-orange.svg)](https://nova.fbi.plus)

[官网](https://nova.fbi.plus) · [下载](https://github.com/sudfiona/NovaProtect/releases) · [详细手册](docs/manual.md) · [开源范围](docs/REPOSITORY-SCOPE.md)

</div>

---

## 目录

- [这是什么](#这是什么)
- [功能](#功能)
- [界面](#界面)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [能力边界](#能力边界)
- [开源范围](#开源范围)
- [文档](#文档)
- [参与贡献](#参与贡献)
- [安全](#安全)
- [许可证](#许可证)

---

## 这是什么

NovaProtect 把目标 PE 里选定的函数或区域翻译成自有指令集，交给内置解释器执行；配合代码变异、反调试、内存保护与导入混淆，使关键逻辑不以原生形式出现在成品里。

仓库里是**客户端和官网的完整源码**：WinUI 3 桌面应用、纯静态官网、集成 SDK、安装器脚本与发布工具。

> **引擎也在仓库里。** VM 指令集、字节码解释器、二次虚拟化器、加密层与 x64 引导桩全部开源，见 [`src/`](src) 与 [`runtime/`](runtime)。唯一的非开源依赖是商业 VMProtect SDK，缺它时构建自动降级，见[开源范围](#开源范围)。

## 功能

| | 能力 | 说明 |
| --- | --- | --- |
| 🧬 | **函数级虚拟化** | 按 SDK marker 或函数扫描结果，把选定区域翻译进虚拟机 |
| 🔀 | **代码变异** | 3 档强度，指令等价替换与膨胀 |
| 🛡️ | **反调试** | 调试器、硬件断点、调试堆、时钟压缩等多路判据 |
| 📦 | **加壳与加密** | 区段压缩、区段加密、导入表保护、资源区段保护、内存完整性 |
| 🥷 | **分析环境对抗** | 关闭 / 均衡 / 激进 / 偏执四档，可逐项微调 |
| 🧹 | **痕迹清理** | 调试目录、重定位、导出目录按需裁剪 |
| 📊 | **可追溯构建** | 输出 `.novaprotect-build.json`，记录请求值与实际生效值 |
| 🖥️ | **桌面客户端** | 项目配置、保存/导入、进度与日志、构建前后对照 |
| 🌐 | **官网与发布工具** | 纯静态站，零后端；打包、校验、版本管理一条龙 |

四档对抗强度各自决定静态擦除、loader 分区域、无 RWX、存在性门控与时序信道的组合，以及 junk / anti_debug / delay / mem_stream 的取值。客户端会把每一档的实际参数列成对照表，避免"以为选了最强"。

## 界面

<div align="center">
<img src="docs/ui-launch-verify.png" width="820" alt="NovaProtect 客户端" />
<br />
<sub>保护项目页：选择目标、调整策略、后台生成受保护版本</sub>
</div>

## 快速开始

### 安装客户端

从 [Releases](https://github.com/sudfiona/NovaProtect/releases) 下载 `NovaProtect-Setup-x.y.z.exe`，运行安装即可。安装包内已带引擎，无需额外配置。

### 从源码构建

公开源码**完整可构建**——引擎、客户端、安装包都能从这份源码编出来：

```bash
git clone https://github.com/sudfiona/NovaProtect.git
cd NovaProtect

powershell -File build.ps1 -Cli       # 保护引擎 -> NovaProtect.Engine.exe
powershell -File build.ps1 -WinUi     # WinUI 3 客户端
powershell -File build.ps1 -All       # 引擎 + 客户端 + 安装包 + 回归
```

只要客户端的话也可以直接用 MSBuild：

```bash
msbuild ui/NovaProtect.UI.csproj /t:Restore               /p:Platform=x64
msbuild ui/NovaProtect.UI.csproj /p:Configuration=Release /p:Platform=x64
```

VMProtect SDK 缺失不影响构建，`build.ps1` 会自动降级到 `NOVAPROTECT_VMP_STUB` 模式（见[开源范围](#开源范围)）。

### 系统要求

| | 要求 |
| --- | --- |
| 运行 | Windows 10 1809 (17763) 或更高，x64 |
| 构建客户端 | .NET SDK 10、Visual Studio 2022+（含 Windows App SDK） |
| 构建安装包 | Inno Setup 6 或 7 |
| 构建引擎产物 | MinGW-w64（`g++` / `objcopy`） |

## 项目结构

```
NovaProtect/
├── src/           保护引擎：VM、二次虚拟化、打包器、变异、反调试、免杀体系
├── include/       引擎头文件：VM 指令集、线格式表、PE 结构、打包器接口
├── runtime/       x64 解释器 prot64.c、引导桩汇编、驱动变异核、托管宿主
├── tests/         引擎与客户端回归测试
├── research/      逆向研究工具：PE 扫描、编码检查、保护器对比
├── ui/            WinUI 3 客户端（页面、模型、服务、样式）
├── website/       官网：纯静态 HTML/CSS/JS + 宝塔/nginx 部署脚本
├── sdk/           集成头文件与示例（NOVAPROTECT_BEGIN/END 标记）
├── installer/     Inno Setup 安装器脚本
├── docs/          设计文档、验证报告、范围声明
├── tools/         打包、校验、版本管理、发布与逆向调试工具
└── build.ps1      统一构建入口
```

官网是**零后端**的：没有 PHP、没有数据库、没有管理面板，解压到任意静态服务器即可打开。上传包与伪静态配置见 [`website/README.md`](website/README.md)。

## 能力边界

只写能证明的能力，不用语言标签包装格式支持：

| 目标 | 状态 |
| --- | --- |
| x64 原生 PE | 完整支持（虚拟化、变异、多区域） |
| x86 原生 PE | 支持（不含 x64 虚拟机） |
| .NET / CLR | 安全封装，**不是** IL 虚拟化 |
| ARM64 | 只读识别，不提供保护 |

虚拟化解释器处理纯寄存器、直线型的 x86-64 子集。访问 `RSP`/`RBP` 或内存、非 `REX.W` 的 32 位操作数、以及 `CALL`/`RET`/`PUSH`/`POP` 等不支持的指令会被**安全跳过**——保留原生代码，功能不受影响。

需要真正虚拟化关键函数时，用 [`sdk/examples/example_vm.S`](sdk/examples/example_vm.S) 的寄存器直通汇编块，函数体至少约 137 字节才可能被虚拟化。

细节见 [详细手册](docs/manual.md)。

## 开源范围

**整个产品都在这份源码里**——引擎、客户端、官网、SDK、安装器、发布工具，全部 MIT 开源：

- ✅ `src/` — VM 引擎、二次虚拟化、打包器、变异、反调试、免杀体系、加密层
- ✅ `include/` — VM 指令集、线格式表、PE 结构定义
- ✅ `runtime/` — x64 解释器 `prot64.c`、引导桩汇编、驱动变异核、托管宿主
- ✅ `tests/` — 引擎与客户端回归测试源码
- ✅ `research/` — 逆向研究工具：PE/编码扫描、ISL 合并校验、保护器对比
- ✅ `ui/` `website/` `sdk/` `installer/` `tools/` `docs/`
- ✅ `build.ps1` — 完整构建入口

不随仓库分发的只有下面这些，理由是法律或安全，不是功能保留：

| 内容 | 原因 |
| --- | --- |
| `third_party/vmprotect/` | 商业授权，禁止再分发。缺它时构建自动降级 |
| Themida / VMProtect Professional 安装目录 | 同样是买来的商业软件 |
| 签名私钥 | 一次性签发凭据 |
| 引擎/宿主二进制、安装包 | 构建产物，属于 [Releases](https://github.com/sudfiona/NovaProtect/releases) |
| `tests/_reg/`（约 90 个打包样本） | 回归输出，不是源码 |
| `*.novaprotect-build.json` | 构建产物，`build.ps1` 重新生成 |
| 样本流量包与沙箱报告 | 是产品的检测证据，不是源码 |

### VMProtect SDK 是可选依赖

引擎链接商业 VMProtect SDK 的标记宏。没有授权时**不需要手工改任何东西**：`build.ps1` 找不到 SDK 就自动定义 `NOVAPROTECT_VMP_STUB`，把标记调用编译成空操作。

```
[vmp] VMProtect SDK not found; building with no-op SDK markers (NOVAPROTECT_VMP_STUB)
[core] compiling NovaProtect.Engine.exe...
[cli] ok
```

买了授权就把 SDK 放进 `third_party/vmprotect/`，构建会自动检测并启用。范围细节见 [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md)你也可以使用泄露版的vmprotect SDK。

## 文档

| 文档 | 内容 |
| --- | --- |
| [详细手册](docs/manual.md) | 免杀子系统、对抗强度分层、验证记录、发布流程 |
| [开源范围](docs/REPOSITORY-SCOPE.md) | 哪些开源、哪些不开源，以及原因 |
| [2.6.0 更新日志](docs/release-notes-client-2.6.0.md) | 客户端面向用户的变更说明 |
| [官网部署](website/README.md) | 上传包、宝塔/nginx 伪静态、部署与回滚 |
| [CHANGELOG](CHANGELOG.md) | 逐版本改动 |

## 参与贡献

欢迎 issue 与 pull request。

- 提交前请确认 `powershell -File build.ps1 -WinUi` 通过
- 客户端改动请附界面截图或 UIA 文本导出
- 官网改动请确保仍是纯静态：不引入 PHP、数据库或后端依赖

## 安全

发现安全问题请**不要**公开提交 issue，通过官网 [https://nova.fbi.plus](https://nova.fbi.plus) 联系维护者。

## 许可证

[MIT](LICENSE) © 2026 NovaProtect

第三方组件遵循各自许可：VMProtect SDK 为商业授权（不随本仓库分发）、Inno Setup 见 `installer/`、Windows App SDK 与 .NET 运行时遵循 Microsoft 条款。
