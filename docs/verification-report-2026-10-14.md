# NovaProtect 功能实现与验证报告

日期：2026-10-14

## 结果

本轮已完成 VMProtect Professional / Themida 静态证据到 NovaProtect 产品能力的映射，并以 2.0.3 完成实现、编译、回归、VMP 兼容封装和安装包验证：

- NovaProtect SDK marker 事实驱动的函数/区域对象编辑器；不支持任意函数伪选择。
- 项目 JSON 保存、导入、导出；构建计划 requested/effective/skipped/conflicts 持久化。
- x86、x64、ARM64、原生 EXE、原生 DLL、.NET 的能力矩阵与 fail-fast/CLR-safe envelope 边界。
- 区段加密启停、重定位裁剪、导出裁剪、导入虚拟化、x64 激活绑定。
- CLI、WinUI、runtime stub 和 x64 protection runtime 的端到端参数传递。

## 关键证据

### Observed

- VMProtect Professional：`VMProtect.exe`，SHA-256 `521d123ad2332c95b2a66e8a0492ed39f6712a999d42593cf46e2052f9385b39`；REA Evidence `ev_3bd1292913fbe29124ef3f7ccce86e46a857250308a211a2db2f66bd0024b077`。
- Themida：`Themida64.exe`，SHA-256 `1fe62f8ea1879b34d5cc711a8999e878e3394896dbd761d8bd95b8d8c51f0e27`；REA Evidence `ev_e1b9dd4be78e5a9f528bc8492ba0c6513991511b2174d3cceb8b4b5a17d82a7e`。
- `build.ps1 -Stub -Prot -Cli -WinUi` 成功：x64 stub 1920 字节、x86 stub 1848 字节、x64 protection runtime 6912 字节、CLI 与 WinUI 均通过编译。
- `tests/regress.ps1` 最终输出 `ALL PASS`。
- `tests/planner-smoke` 输出 `PLANNER-SMOKE-OK`。
- 错误机器 ID 的激活绑定产物在原始入口点前以非零状态终止；`-activation auto` 的 NPP1 flag 和 expected machine ID 与 `-machineid` 输出一致。
- `-noencrypt` 产物的 payload region flags 不包含加密位；产物正常运行。
- `-stripreloc` 产物的 Base Relocation 目录为零、`DYNAMIC_BASE` 被清除且产物正常运行。
- `-stripexport` 产物的 Export 目录为零且产物正常运行；DLL 裁剪请求被 CLI 和规划器阻止。
- marker 选中规则产生 1 个 VM descriptor；skip 和任意偏移伪规则产生 0 个 descriptor。VMProtect SDK 调用目标没有被识别为 NovaProtect marker 对象。
- WinUI 2.0.3 原始构建实例标题 `NovaProtect — 代码保护工作台`，`Responding=True`，文件版本 `2.0.3.0`。
- 2.0.3 五种语言样本均保护并运行成功；日志与输出在 `artifacts\language-support-2.0.3`。
- VMProtect Professional `3.10.3 build 2586` 对 `NovaProtect.UI.dll` 与 `novaprotect.exe` 生成成功；配置开启内存、资源、导入、调试器/虚拟机/内核调试器检查、校验和压缩，`Functions` 保持空集合。
- VMP release 保留 `NovaProtect.UI.exe` apphost，VMP 后 UI 启动、CLI `-machineid`、C++ 样本保护并运行成功。
- Inno Setup `6.7.3` 生成 `NovaProtect-VMProtect-Setup-2.0.3.exe`，大小 `71,552,941` 字节；隔离静默安装成功，安装后 UI 启动并保持响应。
- 安装后的 `NovaProtect.UI.exe` 通过系统图标提取和 REA 静态 PE 资源检查；存在 1 个 `RT_GROUP_ICON`，包含 9 个图标图像候选，资源未消失。

### Inferred

- VMProtect / Themida 的静态资源与 SDK 适合用于产品信息架构和配置分类参考，但不能据此宣称 NovaProtect 达到相同保护强度。
- 对象级“要求激活绑定”当前应解释为对全局 x64 激活前置校验的依赖，不是独立区域授权协议。

### Unknown / remaining boundary

- ARM64 loader 尚未实现；识别后拒绝构建。
- .NET IL/CLR-aware 重写或虚拟化尚未实现；当前使用 CLR-safe 加密 EXE envelope，不改写托管 metadata/IL。
- 尚未实现独立的每 marker 区域激活状态或许可证状态。
- 叠加 VMP 后再对复杂 `test_target.exe` 运行 NovaProtect Ultra/导入保护时观察到退出码 `0xC000001B`；这是叠加保护组合的已知兼容边界。

## 复现

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Stub -Prot -Cli -WinUi
powershell -ExecutionPolicy Bypass -File .\tests\regress.ps1
dotnet run -c Release --project .\tests\planner-smoke\NovaProtect.PlannerSmoke.csproj -- .
.\novaprotect.exe -machineid
```

预期检查点：

- 构建输出包含 `[cli] ok`、`[winui] ok`。
- 回归末尾为 `ALL PASS`。
- planner smoke 为 `PLANNER-SMOKE-OK`。
- 当前机器 ID 为 `6682B60C5C4080A4`。

## 2.0.3 交付哈希与 REA 证据

| 文件 | 大小 | SHA-256 |
| --- | ---: | --- |
| VMP release `novaprotect.exe` | 11,662,848 | `81ECF80182935B0C534B0F786BF6C87CAE36462E04BDBD60F3FD78AC2424952B` |
| VMP release `NovaProtect.UI.exe` | 345,600 | `1E6E174182C6C8791E8D8BF4243FE1F88466B2D41742616A56ADC8428A8CCCB3` |
| VMP release `NovaProtect.UI.dll` | 1,538,048 | `D112747925565F80773A78A1C72301414FD5EA9CBD4C6353C3DAE639ABE61E54` |
| VMP release `NovaProtect.ManagedHost.exe` | 737,706 | `54B9F39BFEC85AF0AB7D34194B076D902BF7EE2E293CB38A15F24528541E36DA` |
| Windows installer | 71,552,941 | `363E10889B5DE269EF0E16824F3AB97645A6AFBE6E6EF837C8EF9808211D531B` |

REA icon-resource evidence:

- 原始 UI：`ev_ff031a2b801f642ecfde06efd5abccafefdab2aa1bb5b550f24133d50de93ef1`
- VMP release UI apphost：`ev_1023ea6b774134e7cc3958549128d31b2a0665dd7f4a244bb47271e145c88005`
- VMP release UI DLL：`ev_9bcd42a9513469595b4d7c0db1ac76ca5b93882fab77a76b09403fb3c1944294`
- VMP release CLI：`ev_a39cd707ad65b92fab9926619ca3fc519228cca0b596af861a3e498970fef7da`
- VMP release managed host：`ev_ed2fa27bd81574f1d9691618798cd02657515c06babfa17db123224eb5d67b5a`
- 安装后 UI：`ev_0d42737d37e4e8c932866f400f06fd66b23607fef52f870ac321c8b4d2f732d1`

流程图见 `docs/protection-flow.mmd`。

