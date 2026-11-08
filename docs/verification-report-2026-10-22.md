# NovaProtect 2.3.0 反沙箱拦截与运行时加固验证报告

- 日期：2026-10-22（Asia/Shanghai）
- 工作区：`artifacts/github-source/NovaProtect-2.3.0`
- 范围：`-sandbox-guard` 打包后必崩修复、反沙箱拦截路径端到端验证、防回归构建断言
- 状态：全部通过（1 项既有环境限制 FAIL 与改动无关）

## 1. 修复的三个缺陷

| # | 缺陷 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | 打包后运行即 `0xC0000409`/`0xC0000005` | 链接脚本 `/DISCARD/` 丢弃 `.bss`，`np_snap_buf` 等静态量为未定义符号，PC 相对引用解析成 `[rip+0x0]`，把代码字节当快照缓冲区遍历 | `.np_bss (NOLOAD)` 保留 VMA；packer 在 blob 后部署 1056 字节零区；`.np_prot` 增加 `SEC_MEM_WRITE` |
| 2 | `-sandbox-threshold 0` 被吞成 40 | 打包器三元判断把显式 0 当「未设置」 | 直写阈值；运行时侧 0 兜底（评分跳过语义保留） |
| 3 | 反沙箱拦截必崩（`np_dbg_report` tag 行 `0xC0000005`），无头沙箱路径同样埋雷 | `kTags`/`kTemplates` 两个 `const char*` 表把链接期绝对地址（0x200005xxx）写进 `.np_rdat`；blob 部署到任意加载基址且无重定位表，指针悬空 | 两表改定宽字符矩阵（`char tag[24]` / `char kTemplates[12][8]`），全部 `lea rip+相对`；宽度由编译器校验 |

第 3 项的定位方法：反调试开启时调试器透明（`anti-debug=0` 打包），npdbg 抓到 `C0000005 @ np_dbg_line+0x1B9`，`cmpb $0,(%rbx)`，rbx=0x20000556C 恰为链接期 `.np_rdat` 内 "+10 script-host-parent" 的绝对地址。全镜像扫描确认仅这 36 个指针（24 kTags + 12 kTemplates），修复后复扫为 0。

## 2. 防回归构建断言（build.ps1 Build-Prot）

1. **绝对指针 tripwire**：链接后扫描 `.np_rdat`/`.np_data` 全部 8 字节窗口，出现 `[link_base, link_base+extent)` 内的值即构建失败，报错信息含偏移、目标地址与修复指引（用定宽矩阵）。对修复前 blob 实测报 36 个，对修复后 blob 报 0。
2. **布局不变量**：`section_VMA − 链接基址 == blob 内偏移`（objcopy `-O binary` 保留 VMA 间隙，节间 `ALIGN(16)` 是正确写法，注释已澄清）；`.np_bss` VMA 必须紧跟 blob 末尾（packer 在此部署静态量零区）；`np_text` 必须从链接基址开始。任一破坏即构建失败。

## 3. 端到端验证矩阵（Observed，全部用修复后 blob 重新打包）

| 场景 | 命令/条件 | 结果 |
| --- | --- | --- |
| 全功能开启 | `anti-debug=2 anti-vm=1 mutation=1 virtualization=1 sandbox-guard=1 sandbox-threshold=40 anti-dump=1 env-check=1 memory-protection=1`，真实桌面 | rc=0，完整正常输出（Hash/Calc/FibMix/Protected），零误报 |
| 仅沙箱默认阈值 | `sandbox-guard=1 sandbox-threshold=40` | rc=0，完整正常输出 |
| 拦截判定 | `sandbox-guard=1 sandbox-threshold=10`，PowerShell 父进程（+10 脚本宿主强信号） | 程序零输出；`%TEMP%\novaprotect-sandbox.log`：`NP-SANDBOX score=10 threshold=10 detail=0x00200000` + `+10 script-host-parent`（tag 行即原崩溃路径） |
| 拦截退出 | 同上，计时 | 3.54s 后 rc=0（notice 线程 3 秒预算 → `ExitProcess(0)`），无崩溃转储 |
| 拦截路径异常监听 | 静态 npdbg（父进程名 sandbox.exe）下运行 | 仅 `0x80000003` 初始断点；`process exited code=0x00000000`，无运行期异常 |
| 评分阶段完整性 | 拦截运行日志 | stage 2-11 全部输出（10 个评分阶段在打包上下文全部可执行） |
| 指令级确认 | objdump 反汇编 | `kTags`/`kTemplates` 访问均为 `lea 0x…(%rip)` + 行步长；无任何绝对指针装载 |
| 回归套件 | `tests/regress.ps1`（test-only core） | 40 OK / 5 SKIP / 1 FAIL |

已知环境限制（与本次改动无关，上一轮同样存在）：5 个 x86 用例因缺 `tests/hostname32.exe`（MinGW 无 32 位工具链）SKIP；planner-smoke「x86 detection failed」同因缺该 fixture。

## 4. 产物

| 文件 | 说明 |
| --- | --- |
| `runtime/prot64.c` | kTags/kTemplates 定宽矩阵化 |
| `runtime/prot64.ld` | `.np_bss (NOLOAD)`；注释澄清 VMA/blob 偏移不变量 |
| `build.ps1` | 节表/VMA 解析、布局断言、绝对指针 tripwire、诊断常量导出 |
| `src/packer.cpp` | bss 零区部署、`.np_prot` 可写、阈值直写（上一轮） |
| `NovaProtect.Engine.exe` | 已用最终 blob 重建（UI 门禁内） |
| `artifacts/test-only-core-2.3.0/CoreRegression.exe` | 回归用测试核心，已重建 |

通用沙箱环境说明：拦截模型覆盖注入 DLL（+25）、模板化计算机名/账户名（kTemplates：win/admin/user/pc-/test/sandbox/virus/malware/analy/cuckoo/joe/sample）、全新安装（<3 天 +10 / <14 天 +6）、1-2 vCPU（+12/+4）、脚本宿主父进程（+10，强信号）、无输入、睡眠压缩等；强信号（NP_SB_STRONG = 0x21C0F）命中且累计分 ≥ 阈值即走「提示 + ExitProcess(0)」拦截路径，不给分析管道留崩溃转储。

## 5. 2.3.1 发布打包与官网升级（追加）

- 版本：客户端 `2.3.0 → 2.3.1`，官网 `2.2.15 → 2.2.16`（两条版本流独立）。
- 全量构建：prot64 blob 19296 字节（+1056 bss），绝对指针 tripwire 报 0；engine / managed host / WinUI 重建；客户端完整性签名 520 文件（RSA-3072/SHA-256，2.3.1）。
- 安装包：`artifacts/client-installer/2.3.1/NovaProtect-Setup-2.3.1.exe`，60,912,479 字节（58.1 MB），SHA-256 `6a4c457f7cfe78f5ea79764f0b68f293cd0c8b76bc8fe442ebdfc68cd552282e`；PE 版本资源内嵌描述为正确中文「NovaProtect Client Installer - 修复反沙箱拦截崩溃；强化运行时稳定性」（UTF-16 校验，无乱码）。
- `website/release.json`：`websiteVersion 2.2.16 / clientVersion 2.3.1 / fileName NovaProtect-Setup-2.3.1.exe / sha256 6a4c457f…`，与安装包实测一致。
- 本地 PHP E2E（PHP 8.5.11 + Inno Setup 7）：`UPDATE-SMOKE-OK`，72 项断言全过——安装向导、管理员登录/登出/限速、匿名更新元数据、下载字节进度、SHA-256 校验、全页面 no-store 响应头。
- 官网部署包（`tools/package-website.ps1`，内置 `verify-website-package.ps1` + `tests/website_installer_test.py` 24 项 OK）：
  - `artifacts/website-full/2.2.16/NovaProtect-Website-2.2.16-Linux-x64-BaoTa-Full.zip`，60,668,592 字节，SHA-256 `4358C354D19C7E216A20B36969767C0119AFD6B88CEFA2ABB4828FA04073F8C8`；
  - `artifacts/website-upgrade/2.2.16/NovaProtect-Website-2.2.16-Linux-x64-BaoTa-Upgrade.zip`，60,661,725 字节，SHA-256 `58352ACCA6BA314B0DE0F0E8152BFCEB5E32F8DF08158C6FA0ED3F92A63F61AB`；
  - 包内 `VERSION=2.2.16`、`release.json`/`package.json` 元数据与内嵌安装包哈希均复核一致；Full 含 `install.sh`，Upgrade 不含（契约测试逐项断言）。
- 打包管线修复（两个与本次发布直接相关的缺陷）：
  1. `tools/version.ps1` 无 BOM，PowerShell 5.1 按 GBK 读取，中文发布说明被双重编码写进 `installer/version.iss`（此前历次安装包版本资源均为乱码，官网更新日志数据源同受影响）。已加 UTF-8 BOM；实测 PS 5.1 读取正确、ISCC 7 无需 BOM 也能正确识别 UTF-8（`novaprotect.iss` 不受影响，有对照实验）。
  2. `tests/update-client-smoke/Program.cs` 强制更新 fixture 写死 `2.3.0`，客户端升过该版本后 `IsNewer` 断言必挂；改为按当前版本动态生成（`Build+1`），不再随升级过期。
- 未运行项：`tools/test-release-update.ps1` 需要仓库中不存在的 probe/inventory 输入（一次性专项 harness），本轮更新契约由上述 PHP E2E 完整覆盖。
- GitHub 源码包（`tools/package-github-source.ps1`，含版本策略检查 + 敏感路径门禁 + 必需文件断言）：
  - `artifacts/github-source/NovaProtect-2.3.1-source.zip`，4.7 MB，234 个文件，SHA-256 `cd9deb2726732219f4512cae551edc410e9e6d9c800333665c882631de5c4b49`（含 `NovaProtect-2.3.1/` 顶层目录）。
  - 独立复核：零敏感泄漏（SDK 二进制 / 签名私钥 / pfx / snk / pdb / vmp 均不在包内）、零构建产物泄漏（bin/obj/artifacts/output/_reg/__pycache__ 均已排除）；`VERSION=2.3.1`、`installer/version.iss` 中文发布说明为正确 UTF-8。
  - 包内二进制均为源码树既有分发内容：`tools/{npdbg,npdump,debugrun}.exe`（调试工具）、`tests/samples/{cpp,csharp,go,rust,vb}-sample.exe` 与 `tests/sandbox_probe.exe`（测试样本）。
