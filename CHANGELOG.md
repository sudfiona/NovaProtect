# 更新日志

本文件记录 NovaProtect 客户端与站点的版本变更。站点 `/client-updates` 的更新说明取自
GitHub Releases（<https://github.com/sudfiona/NovaProtect/releases>），发布时把对应版本的
小节内容贴进 Release 正文即可。

---

## 未发布 — 2026-11-04（2.6.0 之后的客户端界面补全）

> 版本号仍是 2.6.0。客户端调用握手要求签名清单里的版本号与引擎编译期版本号逐字相等，所以
> 升版必须同时 `tools/version.ps1 -Action Sync` 并重建引擎；这一轮没有动版本，只补界面。
> 安装包与官网包已按这一版重打，见文末「重打产物」。

### 客户端补上界面上缺的功能，并给它一个更新日志页

2.6.0 把驱动级与 hypervisor 级能力做进了引擎，但这些能力一个都没接到界面上：命令行能传
`-evasion`、`-kernel-level`、`-hv-exit-cost`，客户端里却没有对应的控件。这一版把缺口补齐，
并且给客户端本身加了一页更新日志 —— 之前想知道客户端改了什么，只能去看 GitHub。

**新页面：对抗与规避**

- 档位选择（关闭 / 均衡 / 激进 / 偏执）+ 可展开的明细表，列出每个档位实际展开成什么。
- 构建签名种子：可生成、可复制、可固定。留空则每次构建从系统熵取新值；固定值可复现同一
  构建，便于定位问题。界面校验 1-16 位十六进制且不为零，格式不对不许保存。
- 动态对抗：垃圾指令密度（0-8）、反沙箱级别（0-3）、内存流式解密轮数（0-3）、引爆延迟
  （0-15000ms，步长 250）、API 反挂钩开关。
- 内核与 hypervisor：驱动探针层级（0-3，每档附说明）、CPUID 退出代价开关。
- 环境闸门：沙箱阈值、环境阈值（0-100），以及处理器数 / 内存 / 运行时长 / 屏幕尺寸 /
  显示器数量六个硬件下限。
- 审计按钮：「审计本机 hypervisor」与「审计本机内核工件」直接调用引擎并打印结论。本机实测：
  `hypervisor PRESENT vendor=Microsoft Hv cpuid=1448c storm=23180c EXIT-COST-ANOMALY score=85`、
  `kernel artifacts 0/40 (device 0, service 0, module 0) tick=plausible score=0`。

**参数怎么落到命令行**

`-evasion <档位>` 会把引擎的整个 `EvasionConfig` 重写成该档位默认值，所以它必须排在所有
逐字段覆盖之前，否则用户调的值会被档位默认值悄悄盖掉。实测发出的命令行：

```
-evasion balanced -junk 2 -anti-sandbox 2 -detonate-delay 2500 -memstream 2 \
-unhook 1 -kernel-level 2 -hv-exit-cost 1 -sandbox-threshold 40 -env-threshold 7
```

引擎回显 `evasion: balanced build=7610b0a01acfb79b static=rich,ts,sect,pdb,pad junk=2
sbx=2 adbg=1 delay=2500ms memrounds=2 unhook=1 hv=vxs kern=2`，逐项对上。

**界面上不再隐藏的东西**

- 保护项目页顶部加一张规避摘要卡，直接显示当前档位、垃圾指令、反沙箱、内核层级，以及环境
  闸门是否启用；右边「调整」按钮跳到对抗与规避页。
- 构建日志新增两行：`规避: <档位> · <详情>`，以及构建结束后的 `命令行: <完整 argv>`。
- 构建计划 JSON 新增 `evasion`、`environment`、`commandLine` 三个字段。没有这些记录，就无法
  判断某个已产出的文件到底是哪套参数压出来的。
- 设置页加「数据与诊断」卡片：打开日志目录、打开配置目录、一键恢复默认规避设置，并直接显示
  两个路径。
- 项目文件 schema 2 → 3，带上规避与环境闸门。打开旧项目不会崩：缺失或为 null 的块会补成默认
  实例，v1 项目照旧走原有迁移。
- 跑之前先校验种子。引擎遇到零种子会以 exit 2 退出，界面现在会提前拦下来并指出是哪个字段。

**新页面：更新日志**

- 从 GitHub Releases 读取，跳过草稿与非语义化版本标签；离线或取不到时回落到随程序打包的版本
  记录，并明确写清「显示的是打包记录」，而不是给一个看起来像坏掉的空白页。
- 正文按纯文本渲染，不做 HTML 注入：标题、列表、表格、代码围栏都压平成可读文本；超过 16 行
  的说明截成预览，末尾给「在 GitHub 查看完整说明」的链接。
- 当前版本打「当前版本」标记。

**修掉的真问题**

- 导航到新页面时窗口直接崩：`XamlParseException ... Failed to assign to property
  'RangeBase.Value'`。根因是 WinUI 在 `InitializeComponent` 解析控件树的过程中就会触发
  `SelectionChanged` / `ValueChanged`，而那些处理器去读还没构造出来的兄弟控件。现在每个处理器
  都先检查「构造是否完成」标志。
- 双击「开始保护」能把整个窗口打崩：`COMException: Only a single ContentDialog can be open at
  any time.`。所有对话框改走统一的串行化通道，第二个请求排队等第一个关掉；真拿不到对话框
  队列时把文字落到构建日志里，至少不丢。
- 规避摘要卡一开始显示成「均衡 · 均衡 · …」，档位名重复。`Summary` 改成只带详情，由调用处
  决定前缀。
- 客户端打开时停在设置页，而设置页没有任何要做的事。默认页改成保护项目，按 `Tag` 选导航项
  而不是按序号，菜单顺序变了也不会错。
- 档位明细表只显示当前档位一列，而均衡档 16 行里有 12 行都是「是」——整张表读起来像同一个值
  重复了 16 次，还把「激进」和「偏执」实际不同的 7 个数值字段全藏了起来。改成四档并排对比，
  表头标出当前档位；`EvasionProfileTable.Row` 覆写 `ToString`，屏幕阅读器不再念
  `Row { Name = ..., Off = ... }`。
- 更新契约冒烟工程用 `<Compile Include>` 直接链接 `ProtectionOptions.cs`，没跟上下层新增的
  `EvasionOptions.cs`，导致 `tools\package-client-release.ps1` 在收尾的 E2E 步骤报
  `CS0246: 未能找到类型 EvasionOptions`。补上链接后 51 项冒烟全过。

**验证**

- `MSBuild` x64 Release 全绿；`CLIENT-INTEGRITY-SIGNED (523 files; RSA-3072/SHA-256; 2.6.0)`。
- 用 63 KB 的真实 x64 目标跑完整流程：`OK! Original: 63362 -> Packed: 145408 bytes`，
  受保护程序执行输出 `5`（源程序 `2+3`），exit 0。
- 两个审计按钮都通过完整的客户端调用握手（命名管道 + 父进程校验 + 签名清单校验）拿到真实本机
  结论，不是桩数据。
- 四档对比表逐单元格实测：`静态特征清洗 | 否 | 是 | 是 | 是`、
  `内存解密窗口 | 全程驻留 | 4096 字节 | 4096 字节 | 4096 字节`、
  `驱动自摘链 | 否 | 否 | 是 | 是`，16 行全部四列有值。
- 默认页实测落在「保护项目」，能看到目标文件输入框。

**重打产物**

- 安装包 `NovaProtect-Setup-2.6.0.exe`，61144502 字节，
  SHA-256 `24715f22f0fbea5fed7470f50d2d7257416ac75d4dba8a2d139bbc6c0bd8f4cf`。
  旧的 `ce621043…` 是 11-03 23:26 编的，不含本轮界面改动，已被覆盖；
  `website/release.json` 同步指向新哈希。
- 更新契约冒烟 `UPDATE-SMOKE-OK (51 checks, version 2.6.0)`：GitHub API 形状、摘要强制、
  重定向主机固定、下载计量、截断与超长响应拒绝全部通过。
- 官网包 `NovaProtect-Website-2.3.0-Linux-x64-BaoTa.zip`，133887 字节，
  SHA-256 `BBAD7CF110EF217FE6781DC01AD2AE6C088EA9D51C391EC74F83EBB98A22D5CB`，
  26 个文件，`WEBSITE-STATIC-ARCHIVE-OK`：清单覆盖全部载荷、无后端、无可执行条目、
  脚本为 LF、站内链接可解析。旧包以 `.20261104-011041.bak.zip` 备份在同目录。
- 同目录新增 `NovaProtect-Website-2.3.0-Linux-x64-BaoTa.zip.sha256`，
  内容 `bbad7cf1…  NovaProtect-Website-2.3.0-Linux-x64-BaoTa.zip`。

**校验清单的完整覆盖**

`SHA256SUMS` 原先只列了 25 行，包里有 26 个文件——差的正是 `SHA256SUMS` 自己。文件装不下
自己的摘要，这一行永远写不进去，所以原先的校验脚本也就默默跳过了它，等于「清单自证」，
被换掉时没有任何东西会发现。现在把这件事做成显式且可机验：

- 打包时断言清单行数等于 staging 里的载荷文件数（在 `SHA256SUMS` 落盘之前计数），
  多加一个文件却没进清单会当场报错。
- 校验时断言覆盖**恰好**完整：除 `SHA256SUMS` 外每个条目都必须在清单里，清单也不许多出
  不存在的条目，行数必须正好是 `条目数 - 1`。
- 在 ZIP 旁边写 `.sha256` 旁挂校验值，作为整包的信任锚——它覆盖 ZIP 的全部字节，因此也
  覆盖了 `SHA256SUMS` 本身。缺少旁挂文件时校验器会明确警告「清单未锚定」，不再静默放过。
- 负例实测：往包里塞一个未列入清单的 `public/extra.html`，校验器报
  `SHA256SUMS does not cover public/extra.html` 并以非零退出，构建不会放过。

**官网新增「上传就能开」的包**

站点原本只有一种产物：带 `install.sh` 的部署包，且页面链接是无扩展名路径（`/download`），
必须靠 vhost 里的 `try_files $uri.html` 才能解析。这意味着把文件直接丢进网站根目录是打不开
的——每个导航链接都会 404。

新增 `tools/package-website-upload.ps1`，产出
`NovaProtect-Website-2.3.0-static-upload.zip`。页面被摆成目录索引：

```
index.html                   /
404.html
download/index.html          /download
client-updates/index.html    /client-updates
privacy/index.html           /privacy
sdk/index.html               /sdk
assets/ css/ js/ data/ favicon.ico
```

目录索引是所有 nginx / Apache 的默认行为，所以解压进网站根目录即可访问，不需要
`try_files`、不需要 root、不需要重启服务。包里不含 `install.sh`、`deploy/`、
`package.json`、`release.json`、`SHA256SUMS`——手动上传的目录没有安装器要向谁交代。

打包时校验：11 个文件、无脚本与可执行文件、四个目录索引都存在且非空、HTML 里**每一个**
绝对路径引用都能在包内解析（`/download` 解析到 `download/index.html`）。

实测：解包后起 `python -m http.server`（零配置），`/`、`/download`、`/client-updates`、
`/privacy`、`/sdk`、`/css/site.css`、`/js/site.js`、`/data/releases.json`、`/favicon.ico`、
`/assets/novaprotect.png` 全部 200，`/nope` 返回 404。

产物 11 个文件，SHA-256 `91C18018EEE2463478DB3B88FD9166DD1DCBE7BDFA803F71BFC49DC11982203D`，
旁挂 `…-static-upload.zip.sha256`。

`install.sh` 的清单比对同时修了一个只在真服务器上现形的 bug：排序用环境 locale、
比较用 `comm` 的字节序，两者不一致时结果错乱，把本来在清单里的文件判成「未列入」。
两侧排序统一到 `LC_ALL=C`，失败时逐个打印未列入清单与列出却不存在的文件名。
四场景实测（干净包 / 多余文件 / 侧挂文件拷入 / 清单列了但文件被删）全部符合预期。

---

## 网站 2.3.0 — 2026-11-03

### 官网去掉后台，改成纯静态

站点原来是个 PHP 应用：PHP 8.4 + PHP-FPM、管理员口令、一次性安装口令、分片上传通道、离线
升级执行器和安装向导。现在这些全部移除，站点只剩静态文件。

**为什么可以删**：客户端更新本来就是 UpdateClient 直连 api.github.com，下载也指向 GitHub
Releases，站点既不托管二进制也不分发版本元数据。后台唯一的用途是"往站点传包"，而后台传上去
的东西客户端根本不读。

**站点现在是什么**：6 个 HTML 页面（首页 / 下载 / 更新日志 / SDK / 隐私 / 404）+ 一份 CSS +
一个 JS + 一份 JSON。

- 内容烘焙在 HTML 里，禁用 JavaScript 也能完整阅读；
- js/site.js 只做一件事：从 data/releases.json 重绘更新日志和版本号，fetch 失败就保持
  烘焙内容不变（不会白屏）；
- 更新日志的发布说明是纯文本渲染，不解析 HTML，避免 Release 正文注入页面。

**下载与版本号**：下载按钮指向 GitHub Releases，页面显示的客户端版本取自已发布的 release，
而不是本地构建号——避免"页面写 2.6.0、GitHub 上是 2.3.33"这种对不上的情况。发布新版本后跑

ode tools/website-build/fetch-releases.mjs 再打包即可。

**打包**：只出一个包
artifacts/website/2.3.0/NovaProtect-Website-2.3.0-Linux-x64-BaoTa.zip。旧的 Full/Upgrade
双包是为 PHP 差分升级准备的；静态站重跑 install.sh 就是升级，第二个产物只会多一个要同步的
东西。打包时自动校验：清单覆盖全部文件且哈希一致、没有 PHP/可执行文件、脚本是 LF、没有未替换
的占位符和后端链接、页面引用的每个地址在包内都存在。

**部署**：install.sh 不再安装 PHP、不创建服务、不生成任何口令。它放文件、从现有 vhost 继承
listen/ssl_*、原子切换 current/previous 槽位、
ginx -t 后重载，然后逐页验证。
ollback.sh、health-check.sh、cdnfly-check.sh 一并改成静态断言：页面全部 200、首页出现
版本标记、未知路径必须返回 404（而不是目录列表或边缘验证页）。

**验证**：包校验 26 个文件、清单完整覆盖；--check-package 从包根、从 deploy/、从任意
工作目录三种方式都通过；篡改页面 / 塞入未列文件 / 塞入 admin.php 三个负例都正确失败；解包
后用静态服务器逐页 200，/admin、/index.php、/api/releases/current 全部 404；
site.js 的 14 项断言通过（含 XSS 载荷只当文本、fetch 失败保留烘焙内容）。

**没变的部分**：客户端更新、安装包分发、GitHub Releases 流程完全不变。

---

## 2.6.0 — 2026-11-03

### 驱动级与 hypervisor 级：接入检测、规避，并接进打包管线

前一个版本只到 PEB / NtGlobalFlag / CPUID leaf1 / RDTSC 这一层。这一版把上面两层补齐，
而且两层都不靠"相信自己发布的标志位"：

**hypervisor 级**
- **vendor 探针**：`CPUID.40000000H.EAX >= 40000000H`。老做法看 `CPUID.1:ECX[31]`，
  一个隐藏自身配置的 hypervisor 会把它清掉；而 leaf 空间无法隐藏 —— 无 hypervisor 时该
  leaf 回显最高基础 leaf（`< 40000000H`），有则回显最高 hypervisor leaf。探针读取
  EBX 里的 12 字节厂商串（VMware / Hyper-V / KVM / Xen / VirtualBox / Parallels / TCG /
  bhyve / ACRN），本机实测识别为 `Microsoft Hv`。
- **exit-cost 探针**：16 次串行 CPUID。裸机每次约 100-200 周期，虚拟化下每次都是一次
  VM exit（1000-5000 周期）。这是唯一"改名改不掉"的判据：hypervisor 可以隐藏厂商串，
  但 CPUID 仍然必须被 trap。本机实测 `23712` 周期 vs `6400` 预算 → 判定为 guest。
- **VMX 屏蔽探针**：hypervisor 在场却是 `CPUID.1:ECX[5]=0`（VT-x 被屏蔽）→ 叠加判据。
- **规避侧**：时间源改读 `KUSER_SHARED_DATA`（`7FFE0320H`）而不是发起系统调用（少一次
  VM exit，监控拿不到调用痕迹）；vendor 探针折叠成单次 CPUID；不使用 RDTSCP/RDPMC。

**驱动级**
- 三类 ring-3 可见的内核痕迹：设备对象（`NtCreateFile` 零权限打开 `\\.\VBoxMiniRdr`
  等 6 个）、驱动服务注册表键（`CurrentControlSet\Services` 下 12 个）、内核模块列表
  （`NtQuerySystemInformation` class 11，13 个 `.sys` 名字）。沙箱会先隐藏它的用户态
  进程，但它藏不掉自己的驱动。
- **tick 连续性**：`KUSER_SHARED_DATA+320H` 在 TSC 计量的数十毫秒内必须前进。注意这个
  字段是约 15.6ms 粒度的时钟节拍、不是毫秒 —— 按毫秒写阈值会让每台机器都"异常"，
  这个错小猫犯过并已修正。
- **kernel_stealth**：探针通过哈希解析 ntdll 导出，不留 IAT 项；不加载驱动、不写注册表。
- **驱动源码发射器**：`-kernel-driver-out` 输出可直接丢进 WDK 的 ring-0 源码 ——
  `IA32_FEATURE_CONTROL`（MSR 3AH）读取、`__cpuidex` 查 hypervisor leaf、
  `KeQueryPerformanceCounter` 与 rdtsc 交叉校验、`IOCTL_NP_HV_QUERY` 上报，
  paranoid 档额外附模块链表自摘链。
- **自摘链的正确做法**：`PsLoadedModuleList` 不在 `ntoskrnl.lib` 的导出里，硬引用编译
  不过、链接也找不到。改走 `DriverObject->DriverSection` —— 它本身就指向该驱动的
  `LDR_DATA_TABLE_ENTRY`，首成员是 `InLoadOrderLinks`，摘链不需要符号查找：

  ```c
  PLIST_ENTRY links = (PLIST_ENTRY)driver->DriverSection;
  if (!links || !links->Flink || !links->Blink) return;
  links->Blink->Flink = links->Flink;
  links->Flink->Blink = links->Blink;
  links->Flink = links;   /* 自环：重复摘链变 no-op */
  links->Blink = links;
  driver->DriverSection = 0;
  ```

**接入打包管线（全部接入）**
- NPP1 描述符新增 `bit15`（exit-cost）与 `bit16`（内核痕迹）；运行时按标志位决定是否
  执行对应层，`-sandbox-guard` 关闭时两层都随分数一起失效。
- 运行时 blob 重新生成：`35424 → 37664` 字节，新增的探针确实进了镜像。
- `-hv-audit` / `-kernel-audit` 打印本机判定与逐条痕迹；`-kernel-level 0-3`、
  `-hv-exit-cost 0|1` 控制深度。
- 档位分配：balanced = 仅 vendor + 内核痕迹；aggressive = 加 exit-cost + tick 连续性；
  paranoid = 再加驱动自摘链。

**验证**
- `tests/evasion_test.cpp` 366 项；`tests/evasion_runtime_test.cpp` **132 项**（新增 45
  项，全为执行级）；端到端 3 项。合计 **501 项断言，0 失败**。
- 新探针在真机上与独立 oracle 逐种子比对：leaf 空间探针 vs `CPUID.40000000H.EAX`
  直读、exit-cost vs 独立 16 次 CPUID 计时、VMX 探针 vs 独立 leaf1 读、stealth vendor
  vs 同一 oracle。
- 打包验证：`-evasion paranoid -sandbox-guard` 打包 `tests/vm_target.exe`，NPP1 标志
  实测 `0xE2A9`（bit15/bit16 均置位），产物 170496 字节，执行 exit code 0。
- **驱动真编译**（WDK `10.0.28000.0` + MSVC `14.51.36231`）：

  | 档位 | 产物 | 字节 | 警告 |
  | --- | --- | --- | --- |
  | plain | `np_hv_plain.sys` | 4608 | 0 |
  | paranoid | `np_hv_paranoid.sys` | 5120 | 0 |

  `cl /kernel /GS- /GR-` 编译、`link /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry`
  链接；PE subsystem 实测 `1`（NATIVE）、入口点 `0x1000`、镜像内含 `NpHvProbe` 设备名。
  脚本 [`tools/build-driver-wdk.ps1`](tools/build-driver-wdk.ps1)，12 项检查。
- **驱动真签名**：`CN=NovaProtect Test Signing` 自签证书，两个 `.sys` 均 `signature
  embedded` + `Authenticode verifies` + `Status Valid`。自签根临时进 `CurrentUser\Root`
  验完即移除，移除后复验按预期失败（反向检查）。脚本
  [`tools/sign-driver.ps1`](tools/sign-driver.ps1)，8 项检查。

**诚实边界**
- 驱动当前状态准确表述：**能编译、能链接、能签名、链能验，加载未验证**。加载自签驱动需要
  `bcdedit /set testsigning on` 加重启，本版本不动这台机器的启动配置，所以"内核态实际
  运行行为"这一格是空的 —— 小猫不假装做过。
- WDK 只用于验证发射器的可构建性。引擎本身不调用 `cl.exe`、不带 WDK 依赖，
  发布物里没有编译器调用。
- 随机化仍然是抬高成本，不是不可检出性的证明。
- hypervisor 检测对"完全隐藏 + CPUID faulting + TSC 缩放"的高级监控仍有盲区，
  exit-cost 只能提高门槛。

---

## 2.5.1 — 2026-11-03

### 验证通过：静态与动态免杀逐项跑真机

不是"编译通过"，是每个模块在真机上被独立判据验证。两套测试合计 **453 项断言，0 失败**：

- `tests/evasion_test.cpp`：366 项（生成器、签名随机化、跨种子唯一性、段名/填充/时间戳规则）。
- `tests/evasion_runtime_test.cpp`：87 项，**执行级**验证 —— 子进程隔离跑每条桩，父进程用
  独立 oracle（CPUID 叶 1 ECX bit31、PEB+2、PEB+0xBC&0x70、自有 rdtsc 对、QPC 墙钟）比对结果。

真机验证覆盖：5 类反沙箱/反调试桩各 12–24 次执行零崩溃且与 oracle 一致；静态免杀打在
`C:\Windows\System32\notepad.exe` 上（MSVC 镜像，真 Rich 头 + 真 PDB 路径）；API unhook 打在
真 `ntdll.dll`（2522 个导出，注入 `E9 rel32` 后再还原，逐字节相同）；白利用计划对 System32
里 10 个宿主全部成立。

### 修掉的真 bug（都是验证逼出来的）

1. **CLI 打包管道根本没有执行静态免杀** —— `packer.cpp` 有两条打包路径，免杀只接在其中一条
   上，`nap -evasion aggressive` 出来的镜像 Rich 头、段名、校验和全是原样。现在两条路径都接。
2. **Rich 头抹不干净** —— 抹除范围停在 `Rich` 字面量本身，后面 4 字节 XOR key 还在，扫描器照样
   认出来。现在抹到 `Rich` 后 8 字节。
3. **校验和写错** —— `updateChecksum()` 对"内存里的 data()"求和，而 `save()` 会用内存段表重写
   段头、并丢掉 overlay，落盘字节与求和对象不一致。用系统自带 `MapFileAndCheckSumW` 复核，
   现在每个输出镜像的校验和与加载器算出来的一致。
4. **白利用宿主名比较区分大小写** —— 目录里的 `InstallUtil.exe` 永远匹配不到 `installutil.exe`
   分支，10 个宿主里 1 个直接 `plan()` 失败。
5. **`-evasion-seed` 拒绝带前导零的 hex** —— BigInteger 导出的种子有前导 0，导致文档里的复现
   流程第一次就报错。

### 整包可复现：种子贯通所有随机阶段

上一版只让免杀层可复现，而载荷密钥、VM 操作码置换、变异引擎、元数据 id 各自取时钟/`random_device`，
所以同一个种子出来的文件仍然不一样（实测 102400 vs 101376 字节）。现在 `Packer::buildSeed()`
一颗种子派全部：载荷密钥、`VMOpcodeMapper` 置换、`MutationEngine`、保护运行时、IAT 密钥、
构建 id。

实测（`tests/vm_target.exe`，`-evasion aggressive -junk 3`）：

- 同一颗种子两次打包 → **SHA-256 相同**，两份都跑出 `VM-OK`。
- 不指定种子连打 4 次 → 4 个不同 SHA-256。
- 指定 3 颗不同种子 → 3 个不同 SHA-256；manifest 的 tag/filler/probe_order/nonce/timestamp 全不同。

### 边界（照旧诚实）

随机化提高的是检测成本，不是不可检测的证明；反沙箱桩只覆盖 PEB、NtGlobalFlag、CPUID 叶 1、
时序四类，没有覆盖驱动级或 hypervisor 级检测。junk/dynamic/loader/unhook/white 仍属引擎侧 +
运行时代码发射器，`NPP1` 部署标志尚未接进打包流程。

---

## 2.5.0 — 2026-11-02

### 新增：手动刷新随机免杀特征（`src/evasion_entropy.cpp`、`src/evasion_variants.cpp`）

2.4.0 的生成器是**固定字节**：探针、花指令组合、段名、填充全是常量，一个特征码就能覆盖
产品出过的所有镜像。这一版把每个生成器的编码选择都挂到一个 64 位种子上。

**每次都不一样**

- `EvasionConfig::planSignature()` 从系统熵取种子（`BCryptGenRandom` + QPC + TID/PID +
  RDTSC 抖动），一次规划出：`build_tag`（16 位十六进制）、16 字节 DOS 桩随机数、
  段名后缀、填充字节、花指令预算、探针顺序、密钥盐、时间戳。
- 原来 `seed=0` 会退化成固定常量 `0x53544456`，于是每次构建出的镜像字节相同 —— 这是上一版
  的真实缺陷，现在 `0` 明确表示"现场取熵"。
- DOS 桩区域（`0x40`–`e_lfanew`，`This program cannot be run in DOS mode` 那 64 字节）不再
  清成 0，而是写入本次构建的随机数。扫描器看这里一直是一模一样的 64 个零，本身就是特征。
- 段名走 `.text$` + 随机两位后缀的 MSVC 组名格式，填充字节从 6 个候选里取，抖动都落在
  VirtualSize 之外的死区。

**确定可复现**

种子 → 字节是纯函数。种子写进 manifest，`-evasion-manifest-in` 能一字不差重建同一个镜像，
所以"每次不一样"是可验证的，不是口号。

**手动刷新入口**

```
-evasion-reseed             丢掉当前计划，现场取新熵（手动刷新）
-evasion-seed <hex>         指定 64 位种子（复现某次构建）
-evasion-manifest-out <f>   写出本次签名清单（JSON）
-evasion-manifest-in  <f>   用旧清单的种子重建
```

`Packer::pack` 的 `PackResult` 新增 `evasion_build_tag` 与 `evasion_seed`，构建日志直接打印，
出问题凭 tag 就能定位到具体一次构建。

### 新增：`StubForge`（随机探针编码）

同一语义多种等长/不等长编码，按种子选：CPUID 判定（`shr`/`bt`+`setc`/`test imm32`+
`setne`/`shr ecx`）4 种、PEB 读取 4 种、`NtGlobalFlag` 掩码 4 种、RDTSC 序列化与重组
（`cpuid` 两种装载 × `or`/`add` × 寄存器 r9/r10/r11 × `cmp` 两种）× 24、延迟门 9 种；
再叠加每处 0–3 个透明花指令块。

组合例程的探针顺序按种子排（24 种全排列），分发指令在 `test`/`or` + `je rel32`/`jz rel8`
之间选，返回 id 用 `mov eax,imm32` 或 `push imm8; pop rax`。

### 测试

`tests/evasion_test.cpp` 扩到 **366 项断言**，新增：

- 2000 个种子 → 2000 个互不相同的 `build_tag` 与密钥盐（唯一性）；
- 同种子两次规划完全一致（可复现性）；
- 300 个种子的填充字节 / 花指令预算 / 探针顺序分布（24 种全排列都出现）；
- 256 个种子的组合探针两两不同，且结构检查（以 RET 结尾、无 INT3）全通过；
- 两个种子的静态镜像有 > 32 字节差异，且 DOS 桩不再是全零；
- manifest JSON 往返，缺 `seed` 的清单被拒。

### 说明（边界，不夸大）

- 探针编码是人工逐条核对 + 仓库自带反汇编器覆盖范围内校验的；**没有执行级验证**：
  本机没有 x64 执行沙箱，编出来的字节没有真正跑过。要坐实语义，需要在目标机上跑
  `emitCombinedProbe` 的产物并比对返回 id。
- 反汇编器不覆盖 `lfence`、`mov r64, imm64`、多字节 `nop`，遇到时会把后续字节错位读成
  `CALL`/`RET`。`DynamicEvader::verifyStub` 因此只在能识别的指令上判定；随机化产物的
  结构检查放在测试里单独做（以 RET 结尾、无 INT3、跨种子互不相同）。
- 随机化提高的是静态匹配与启发式的成本。是否被某个引擎判黑，取决于载荷、引擎版本和当天
  的规则，这里不做保证。

---

## 2.4.0 — 2026-11-02

### 新增：免杀子系统（`include/evasion*.h`、`src/evasion*.cpp`、`src/junk_emitter.cpp`、
`src/api_unhook.cpp`、`src/mem_loader.cpp`、`src/white_launcher.cpp`）

一个 `EvasionConfig` 驱动六族生成器，四档预设 `off / balanced / aggressive / paranoid`，
每个开关都能单独改，方便表达「paranoid，但保留时间戳」这种组合。

**静态免杀**（成品镜像后置阶段，已接进 `Packer::pack`）

| 步骤 | 作用 |
| --- | --- |
| Rich header + DOS 桩擦除 | 擦掉 `Rich` 签名与 `This program cannot be run in DOS mode` 桩，抹掉工具链指纹 |
| `TimeDateStamp` 随机化 | 换成 2021–2026 之间的合理构建时间，避免一眼假时间戳 |
| 段名规范化 | 非 `.np*` 段改写成链接器会产出的名字（`.text` / `.rdata` / `.data` / `.bss`） |
| CodeView / PDB 清除 | 清空 `IMAGE_DEBUG_TYPE_CODEVIEW` 条目并复位调试目录，不泄漏构建机路径 |
| 段尾填充去零 | `SizeOfRawData > VirtualSize` 的空白用花指令块填满，去掉「整片 0」这个强指纹 |
| 失效签名清理 | 改写后 Authenticode 摘要必然失效，直接清掉目录；坏签名比没签名更容易被盯上 |
| 校验和重算 | 最后一步按落盘后的完整镜像重算 `CheckSum`，不是按内存里的旧数据 |

**花指令**（`JunkEmitter`）六种寄存器/标志位透明的 x64 块：`pushfq/popfq` 包裹的零立即数
编码、两条不透明谓词分支（`cmp rsp,0` / `test rsp,rsp`）、`xchg [rsp],rax` 往返、`add rax,0`、
`rol/ror` 成对。另有死分支诱饵块（跳转位移精确等于诱饵长度）与段间填充。

**动态免杀**（`DynamicEvader`）

- 主机评分模型：加权信号累加，**只有「分数达阈值 且 命中强证据」才阻断**。强证据＝模板化
  机器名、分析厂商模块、调试器附加；空载虚拟机分数再高也不拦。
- 五段手写 x64 探针（无导入表、`uint32_t fn(void)` 契约）：CPUID hypervisor 位、PEB
  `BeingDebugged`、`NtGlobalFlag & 0x70`、RDTSC/CPUID 序列化时序、RDTSC 截止时间延迟门。
- `verifyStub` 用仓库自带反汇编器逐条解码校验，而不是扫字节。

**加载器与内存混淆**（`MemLoader`）

- 按段生成加密计划（`NPMP`），每段独立密钥、按 4 KB 窗口、可多轮；密钥流是纯 XOR，因此
  加密与解密是同一个函数，可被单测证明。
- 记录每段最终保护属性（`PAGE_EXECUTE_READ` / `PAGE_READWRITE` / `PAGE_READONLY`），
  运行时按 RW→RX 过渡，不再需要一个整块 RWX 分配。

**API unhooking**（`UnhookEngine`）

- 干净磁盘镜像 vs 内存镜像逐字节比对，合并间隔小于阈值的差异段，产出 `NPUH` 还原表。
- 独立的内联钩子形态扫描：`E9 rel32`、`FF 25 disp32`、`48 B8 … FF E0`、`68 imm32 C3`、`EB rel8`。
- `emitRuntimeSource()` 输出可直接编译的 C 还原驱动骨架。

**白利用**（`WhiteLauncher`）

10 个微软签名宿主的参数模板（rundll32 / regsvr32 / mshta / certutil / conhost /
InstallUtil / mavinject / wscript / cmstp / forfiles），生成精确 argv、前置条件与
`.cmd` / JSON 清单；`validateSideLoad` 会拒掉 KnownDLLs 里的名字（那些永远从 System32 解析）。

### 新增：命令行开关

```
-evasion <off|balanced|aggressive|paranoid|0-3>
-no-evasion
-junk <0-8>                 -anti-sandbox <0-3>        -detonate-delay <ms>
-memstream <0-3>            -unhook <0|1>
-evasion-audit              报告输入的静态可检出面（Rich/PDB/签名/零填充/段熵/高危导入）
-white-plan <host>          打印签名宿主启动计划
```

`-evasion-audit` 只报数不做"修复"声明：段熵、零填充字节数、高危导入名都原样列出，
方便和外部扫描器对账。

### 新增：测试

`tests/evasion_test.cpp`，82 项断言，覆盖花指令透明性与 `pad()` 尺寸、探针可解码性、
自逆密钥流、`NPUH`/`NPMP` 表往返、静态免杀副作用、宿主评分边界（高分无强证据不阻断）。

### 变更：GitHub 仓库对接

- `website/github.json` → `{"repo": "sudfiona/NovaProtect"}`
- 客户端 `ui/Models/ProtectionOptions.cs`：`GitHubRepository`、`GitHubRepositoryUrl`、
  `GitHubReleasesUrl`、`GitHubLatestReleaseUrl` 一并指向该仓库
- 安装器 `AppUpdatesURL` 指向 releases/latest
- 站点安装向导不再因为「未配置仓库」被拦住

改仓库时这四处要一起改，否则站点与客户端会指向不同发布源（README 已注明）。

### 接入状态（说明范围）

| 能力 | 状态 |
| --- | --- |
| 静态免杀 | **已接入**打包流程，成品镜像直接生效 |
| 花指令 / 动态探针 / 加载器 / unhooking / 白利用 | 引擎侧生成器与运行时驱动源码输出已就绪，通过 CLI 与新 API 可取用；载荷侧（NPP1 旗标 + `.np_prot`）部署开关尚未翻转 |

这一栏写清楚是为了避免"纸面上受保护"：没有接进载荷的能力，不当成已生效来宣传。

---

## 2.3.33

- 沙箱对抗强化；延时复测默认开启。
