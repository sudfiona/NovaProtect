# 仓库范围说明

本仓库是 NovaProtect 的**完整开源源码**：引擎、客户端、官网、SDK、安装器与发布工具全部在内。本文说明开源范围，以及哪些内容因法律或安全原因不随仓库分发。

## 开源内容

| 路径 | 内容 |
| --- | --- |
| `src/` | 保护引擎：VM 引擎、二次虚拟化、打包器、变异、反调试、免杀体系、加密层、client gate |
| `include/` | 引擎头文件：VM 指令集、线格式表、PE 结构定义、打包器接口 |
| `runtime/` | 运行时源码：x64 解释器 `prot64.c`、引导桩汇编、驱动变异核、托管宿主 |
| `tests/` | 回归与验证测试源码：VM 引擎、变异、反调试、免杀、UI 逻辑、更新客户端 |
| `research/` | 逆向研究工具：PE/编码扫描、ISL 合并校验、保护器对比脚本 |
| `ui/` | WinUI 3 客户端 |
| `website/` | 官网纯静态站 + 宝塔/nginx 部署脚本 |
| `sdk/` | 集成头文件与示例 |
| `installer/` | Inno Setup 安装脚本 |
| `tools/` | 发布工具与逆向调试工具 |
| `docs/` | 设计文档、验证报告、营销生成脚本 |
| `build.ps1` | 统一构建入口 |

## 不随仓库分发的内容

这些不是"藏起来的功能"，而是**法律上不能再分发**或**本来就不该入库**的东西：

| 内容 | 原因 |
| --- | --- |
| `third_party/vmprotect/`（`VMProtectSDK64.dll` / `.a` / `.lib` / `.h`） | 商业授权，禁止再分发。缺它时构建自动降级，见下文 |
| `Themida`、`VMProtect Professional` 安装目录 | 同样是买来的商业软件，不能随仓库公开 |
| 签名私钥（`client-integrity.key.xml`、`artifacts/private-signing/`） | 一次性签发凭据，泄漏即失守 |
| 引擎与宿主二进制、安装包 | 构建产物，属于 Releases |
| `*.novaprotect-build.json` / `*.novaprotect-prebuild.json` | 构建产物，`build.ps1` 会重新生成 |
| `tests/_reg/`（约 90 个打包样本） | 回归输出，不是源码；生成它的驱动脚本已开源 |
| 微步分析报告与 PCAP 样本 | 是产品的检测证据，不是源码 |
| `docs/marketing-build/render/` | 营销售页渲染产物；生成脚本已开源 |
| `.work-backup-*/` | 过期源码副本，会与真实源码冲突 |

## 可构建性

**这份源码可以完整构建出保护引擎和客户端。**

商业 VMProtect SDK 缺失时不需要任何手工干预：

```
[vmp] VMProtect SDK not found; building with no-op SDK markers (NOVAPROTECT_VMP_STUB)
[core] compiling NovaProtect.Engine.exe...
[cli] ok
```

`build.ps1` 会调用 `tools/resolve-vmprotect-sdk.ps1` 找 SDK；找不到就自动定义 `NOVAPROTECT_VMP_STUB`，把标记调用编译成空操作。标记调用点在 `src/client_gate.cpp` 与 `runtime/managed_host.cpp` 里完全一致，只有 `include/vmp_markers.h` 的 `#ifdef` 分支不同。

想要 VMProtect 那层额外保护，自行购买授权后把 SDK 放到 `third_party/vmprotect/`，`build.ps1` 会自动检测并使用。

实测（无 SDK、无 `version-lock.json` 的干净解压）：

```
build.ps1 -Cli  ->  NovaProtect.Engine.exe  3,892,219 bytes  build complete
```

## 安全设计

裁剪由 `tools/package-github-source.ps1` 强制执行，不是手工约定：

- `$engineRequired` 断言引擎源码**确实在**包里——排除规则若误伤 `src/`/`runtime/`，打包直接失败；
- `$forbidden` 断言商业 SDK 与私钥**确实不在**包里；
- `$banned` 拦截签名凭据类路径；
- `tools/audit-github-source.ps1` 对成品包做独立复核：私钥、商业 SDK、构建产物、样本、许可证、维护者本机路径、引擎完整性。

## 版本

客户端与官网版本独立递增。当前版本以 `VERSION` 与 `website/VERSION` 为准，安装包的 SHA-256 以 `website/release.json` 为准（由发布流程自动写入）。
